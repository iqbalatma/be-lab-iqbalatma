<?php

namespace App\Console\Commands;

use App\Events\PermissionChangedEvent;
use App\Events\RoleChangedEvent;
use Illuminate\Console\Command;

class ClearCacheCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:clear-cache';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clear cache via event trigger';

    /**
     * Execute the console command.
     */
    public function handle():void
    {
        $this->info("Start clearing application cache");
        RoleChangedEvent::dispatch();
        PermissionChangedEvent::dispatch();
        $this->info("Clearing application cache completed");
    }
}
