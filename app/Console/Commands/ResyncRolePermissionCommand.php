<?php

namespace App\Console\Commands;

use App\Enums\Role;
use App\Events\PermissionChangedEvent;
use App\Events\RoleChangedEvent;
use App\Models\Permission;
use Illuminate\Console\Command;

class ResyncRolePermissionCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:resync-role-permission';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Resync role and permission';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info("Start resync role and permission");
        #role resync
        foreach (Role::cases() as $role) {
            \App\Models\Role::query()->updateOrCreate(
                [
                    "name" => $role->value,
                ],
                [
                    "name" => $role->value,
                    "is_mutable" => false,
                ],
            );
        }

        #permission resync
        $actualPermissionNames = [];
        foreach (\App\Enums\Permission::cases() as $permission) {
            $actualPermissionNames[] = $permission->value;
            Permission::query()->updateOrCreate(
                [
                    "name" => $permission->value
                ],
                [
                    "name" => $permission->value,
                    "feature" => $permission->featureGroup(),
                    "description" => $permission->description()
                ]
            );
        }

        Permission::query()->whereNotIn("name", $actualPermissionNames)->delete();


        RoleChangedEvent::dispatch();
        PermissionChangedEvent::dispatch();
        $this->info("Resync role and permission successfully");
    }
}
