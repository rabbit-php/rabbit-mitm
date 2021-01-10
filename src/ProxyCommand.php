<?php

declare(strict_types=1);

namespace Rabbit\Mitm;

use Throwable;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class ProxyCommand extends Command
{
    /**
     *
     */
    protected function configure(): void
    {
        $this->setName('proxy:server')->setDescription('start|stop|reload proxyserver')
            ->setHelp('This command allows you to start|stop|reload proxyserver.')
            ->addArgument('cmd', InputArgument::REQUIRED, 'start|stop|reload');
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     * @throws Throwable
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $cmd = $input->getArgument('cmd');
        getDI('proxy')->$cmd();
        return Command::SUCCESS;
    }
}
