<?php

namespace App\Services\Management;

use App\Exceptions\InvalidActionException;
use App\Models\Role;
use App\Repositories\RoleRepository;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelServiceRepo\Attributes\ServiceRepository;
use Iqbalatma\LaravelServiceRepo\Contracts\Interfaces\DeletableRelationCheck;
use Iqbalatma\LaravelServiceRepo\Exceptions\DeleteDataThatStillUsedException;
use Iqbalatma\LaravelServiceRepo\Exceptions\EmptyDataException;

#[ServiceRepository(RoleRepository::class)]
class RoleService extends \App\Contracts\Abstracts\BaseService
{
    /**
     * @return Collection
     */
    public static function getAllCachedData(): Collection
    {
        $key = config('cache.keys.all_roles');
        if (!($roles = Cache::get($key))) {
            $roles = Role::query()->get();
            Cache::put($key, $roles);
        }
        return $roles;
    }

    /**
     * @param array $requestedData
     * @return Role
     */
    public function addNewData(array $requestedData): Role
    {
        /** @var Role $role */
        $role = $this->repository->addNewData($requestedData);

        if (isset($requestedData["permission_ids"])){
            $role->givePermissionTo($requestedData["permission_ids"]);
        }

        return $role;
    }

    /**
     * @param string|int $id
     * @param array $requestedData
     * @return Role
     * @throws EmptyDataException
     */
    public function updateDataById(string|int $id, array $requestedData): Role
    {
        $this->checkData($id);
        /** @var Role $role */
        $role = $this->getServiceEntity();


        if (isset($requestedData["permission_ids"])){
            $role->givePermissionTo($requestedData["permission_ids"]);
        }

        return $role;
    }

    /**
     * @param string|int $id
     * @return int|array
     * @throws DeleteDataThatStillUsedException
     * @throws EmptyDataException
     * @throws InvalidActionException
     */
    public function deleteDataById(string|int $id): int|array
    {
        $this->checkData($id);
        /** @var Role $entity */
        $entity = $this->getServiceEntity();
        if (!$entity->is_mutable){
            throw new InvalidActionException("This entity cannot be deleted");
        }
        if ($entity instanceof DeletableRelationCheck) {
            $this->checkIsEligibleToDelete($entity);
        }

        return $entity->delete();
    }
}
