<?php

namespace App\Services\Master;

use App\Models\Permission;
use App\Models\Role;
use App\Services\Management\PermissionService;
use App\Services\Management\RoleService;
use Illuminate\Support\Collection;
use Iqbalatma\LaravelServiceRepo\BaseService;

class AuthorizationService extends BaseService
{
    /**
     * @return Collection
     */
    public static function getAllRoles(): Collection
    {
        return RoleService::getAllCachedData()->transform(function (Role $role) {
            return [
                "id" => $role->id,
                "name" => $role->name,
            ];
        });
    }

    /**
     * @return Collection
     */
    public static function getAllPermissions(): Collection
    {
        return PermissionService::getAllDataCached()->transform(function (Permission $permission) {
            return [
                "id" => $permission->id,
                "name" => $permission->name,
                "feature" => $permission->feature,
                "description" => $permission->description,
            ];
        });
    }
}
