<?php

namespace App\Providers;

use App\Events\PermissionChangedEvent;
use App\Events\RoleChangedEvent;
use App\Listeners\ClearCache\ClearPermissionCacheListener;
use App\Listeners\ClearCache\ClearRoleCacheListener;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }


    /**
     * @return \class-string[][]
     */
    public static function listen(): array
    {
        return [
            RoleChangedEvent::class => [
                ClearRoleCacheListener::class
            ],
            PermissionChangedEvent::class => [
                ClearPermissionCacheListener::class
            ]
        ];
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        foreach (self::listen() as $event => $listeners) {
            foreach ($listeners as $listener) {
                Event::listen($event, [$listener, 'handle']);
            }
        }
    }

}
