<?php

namespace App\Listeners\ClearCache;

use App\Events\RoleChangedEvent;
use Illuminate\Support\Facades\Cache;

class ClearRoleCacheListener
{
    /**
     * Create the event listener.
     */
    public function __construct()
    {
        //
    }

    /**
     * Handle the event.
     */
    public function handle(object $event): void
    {
        /** @var RoleChangedEvent $event */
        Cache::forget(config('cache.keys.all_roles'));
    }
}
