<?php

declare(strict_types=1);

namespace Rabbit\Mitm;

use Rabbit\Base\App;
use Rabbit\Base\Helper\FileHelper;
use Rabbit\Server\CoServer;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Throwable;

class ProxyServer extends CoServer
{

    protected array $handlers = [];

    protected ?string $filePath = null;

    protected function createServer()
    {
        return new Server($this->host, $this->port, $this->ssl, true);
    }

    protected function startServer($server = null): void
    {
        $this->filePath = $this->filePath ?? sys_get_temp_dir() . '/mitmrabbit';
        FileHelper::createDirectory($this->filePath, 777);
        parent::startServer($server);

        $server->handle(function (Connection $conn) {
            $socket = $conn->exportSocket();
            $status = 1;
            $ssl = false;
            $remote = null;
            $needRequest = true;
            try {
                while (strlen((string)$data = $conn->recv()) > 0) {
                    try {
                        $needRequest && $request = new \http\Message($data);
                    } catch (Throwable $e) {
                        App::error($e->getMessage() . '. remove body');
                        $request = new \http\Message(current(explode("\r\n\r\n", $data)));
                    }

                    if ($status === 1) {
                        $ssl = $request->getRequestMethod() === 'CONNECT';
                        $urlStr = $request->getRequestUrl();
                        $url = parse_url($urlStr);
                        $host = $url['host'];
                        $port = $url['port'] ?? ($ssl ? 443 : 80);
                        $status = 2;
                        App::info("MITM to " . $urlStr);
                        if ($ssl) {
                            $remote = stream_socket_client("ssl://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, stream_context_create([
                                'ssl' => [
                                    'capture_peer_cert' => true,
                                    'capture_peer_cert_chain' => true,
                                ],
                            ]));
                            $x509 = openssl_x509_parse(stream_context_get_params($remote)['options']['ssl']['peer_certificate'], true);
                            if ($x509 === false) {
                                return;
                            }
                            $subject = $x509['subject'];
                            $cn = 'rabbit-' . $subject['CN'];
                            if (!file_exists("{$this->filePath}/$cn.crt") || !file_exists("{$this->filePath}/$cn.key")) {
                                static $pkey, $pCert;
                                $pkey = file_get_contents(App::getAlias('@root/server_key.pem'));
                                $pCert = file_get_contents(App::getAlias('@root/server_cert.pem'));
                                $sna = explode(', ', str_replace('DNS:', '', $x509['extensions']['subjectAltName']));
                                $this->writeSSLCnf("{$this->filePath}/$cn.cnf", $sna);
                                $config = [
                                    "digest_alg" => "sha256",
                                    'config' => "{$this->filePath}/$cn.cnf"
                                ];
                                $dn = array(
                                    "countryName" => $subject['C'] ?? 'CN', //所在国家名称    
                                    "stateOrProvinceName" => $subject['ST'] ?? 'GuangDong', //所在省份名称    
                                    "localityName" => $subject['L'] ?? 'GuangZhou', //所在城市名称    
                                    "organizationName" =>  $subject['O'] ?? 'LaoYao',   //注册人姓名     
                                    "commonName" => current(explode(':', $request->getHeaders()['Host'])) //公共名称
                                );
                                $csr = openssl_csr_new($dn, $pkey, $config);
                                $sscert = openssl_csr_sign($csr, $pCert, $pkey, 3 * 365, $config, intval(microtime(true) * 1000));
                                openssl_pkey_export_to_file($pkey, "{$this->filePath}/$cn.key", null, $config);
                                openssl_x509_export_to_file($sscert, "{$this->filePath}/$cn.crt");
                                @unlink("{$this->filePath}/$cn.cnf");
                            }
                            $socket->setProtocol([
                                'open_ssl' => true,
                                'ssl_key_file' => "{$this->filePath}/$cn.key",
                                'ssl_cert_file' => "{$this->filePath}/$cn.crt"
                            ]);
                            $socket->send("HTTP/1.1 200 Connection Established\r\n\r\n");
                            $socket->sslHandshake();
                            continue;
                        }
                        $remote = stream_socket_client("tcp://$host:$port", $errno, $errstr, 30);
                    }

                    $needRequest = false;
                    fwrite($remote, $data);
                    $response = Agent::getResponse($remote, $socket);
                    if (array_key_exists($host, $this->handlers) && $response !== null) {
                        rgo(fn () => $this->handlers[$host]($request, $response));
                    }
                }
            } catch (Throwable $e) {
                App::error($e->getMessage());
                echo $data . PHP_EOL;
            } finally {
                $conn->close();
            }
            $conn->close();
        });
        $server->start();
    }

    public function writeSSLCnf(string $filename, array $config)
    {
        $fp = fopen($filename, "w+");
        // Write basic configurations
        fwrite(
            $fp,
            <<<EOF
        [req]
        req_extensions = extension_section
        x509_extensions	= extension_section
        distinguished_name = dn
         
        [dn]
         
        [extension_section]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment
        subjectAltName = @alt_names
         
        [alt_names]
        EOF
        );

        // Write SANs
        foreach ($config as $key => $value) {
            fwrite($fp, sprintf("\nDNS.%d = %s", $key + 1, $value));
        }

        // Close configuration pointer
        fflush($fp);
        fclose($fp);
    }
}
