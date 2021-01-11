<?php

declare(strict_types=1);

namespace Rabbit\Mitm;

use Rabbit\Base\App;
use Swoole\Coroutine\Socket;
use Swow\Buffer;
use Throwable;

class Agent
{
    public static function getResponse($client, Socket $socket): ?\http\Message
    {
        $headerStr = new Buffer(0);
        $status = '';
        $isChunked = false;
        $contentLength = 0;

        try {
            while (!feof($client)) {
                $data = fgets($client);
                if ($data === "\r\n") {
                    break;
                } elseif ($data === false || $data === '') {
                    return null;
                }
                $headerStr->write($data);
            }
            $headerStr->write("\r\n");
            $socket->send($headerStr->toString());

            $headers = preg_split("#\r\n#i", $headerStr->toString(), -1, PREG_SPLIT_NO_EMPTY);
            foreach ($headers as $header) {
                if (preg_match("#^HTTP/#", $header)) {
                    if (preg_match("#^HTTP/[^\s]*\s(.*?)\s#", $header, $status)) {
                        $status = $status[1];
                    }
                } elseif (preg_match('#^Transfer-Encoding:\s*chunked#i', $header)) {
                    $isChunked = true;
                } elseif (preg_match('#^Content-Length:\s*(\d+)#i', $header, $len)) {
                    $contentLength = (int)$len[1];
                }
            }

            if (substr($status, 0, 2) === "20") {
                $send = new Buffer(0);
                if ($isChunked) {
                    while (!feof($client)) {
                        $data = fgets($client);
                        if (!$data) {
                            break;
                        }
                        $send->write($data);
                        if ($data === "\r\n") {
                            break;
                        }
                    }
                    stream_set_blocking($client, false);
                    while (strlen((string) ($tmp = fread($client, 2048))) > 0) {
                        $send->write($tmp);
                        $socket->send($tmp);
                    }
                    stream_set_blocking($client, true);
                    $send->rewind();
                    while (!$send->eof()) {
                        $len = $socket->sendAll($send->toString());
                        $send->seek($len);
                    }
                } elseif ($contentLength > 0) {
                    //读取请求返回的主体信息
                    while (!feof($client)) {
                        $send->write(fread($client, $contentLength));
                        //当读取完请求的主体信息后跳出循环，不这样做，貌似会被阻塞！！！
                        if ($send->getLength() >= $contentLength) {
                            break;
                        }
                    }
                    stream_set_blocking($client, false);
                    while (strlen((string) ($tmp = fread($client, 2048))) > 0) {
                        $send->write($tmp);
                        $socket->send($tmp);
                    }
                    stream_set_blocking($client, true);
                    $socket->sendAll($send->toString());
                }
                return (new \http\Message($headerStr->write($send->toString())->toString()));
            }
            return null;
        } catch (Throwable $e) {
            App::error($e->getMessage());
            return null;
        }
    }
}
