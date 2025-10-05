<?php

namespace App\Services\Management;

use App\Contracts\Abstracts\BaseService;
use App\Models\Permission;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class PermissionService extends BaseService
{
    /**
     * @return Collection
     */
    public static function getAllDataCached(): Collection
    {
        $key = config("cache.keys.all_permissions");
        if (!($permissions = Cache::get($key))) {
            $permissions = Permission::query()->get();
            Cache::put($key, $permissions);
        }

        return $permissions;
    }
}
