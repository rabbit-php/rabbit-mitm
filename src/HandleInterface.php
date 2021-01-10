<?php

declare(strict_types=1);

namespace Rabbit\Mitm;

interface HandleInterface
{
    public function __invoke(\http\Message $request, \http\Message $response): void;
}
