<?php

namespace App\Listeners\ClearCache;

use App\Events\PermissionChangedEvent;
use Illuminate\Support\Facades\Cache;

class ClearPermissionCacheListener
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
        /** @var PermissionChangedEvent $event */
        Cache::forget(config('cache.keys.all_permissions'));
    }
}
