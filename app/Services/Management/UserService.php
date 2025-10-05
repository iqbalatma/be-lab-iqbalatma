<?php

namespace App\Services\Management;

use App\Contracts\Abstracts\BaseService;
use App\Models\User;
use App\Repositories\UserRepository;
use Illuminate\Support\Facades\Hash;
use Iqbalatma\LaravelServiceRepo\Attributes\ServiceRepository;

#[ServiceRepository(UserRepository::class)]
class UserService extends BaseService
{
    /**
     * @param array $requestedData
     * @return User
     */
    public function addNewData(array $requestedData): User
    {
        $this->setRequestedData($requestedData);
        $this->updateRequestedData("password", Hash::make($requestedData["password"]));

        /** @var User $user */
        $user = $this->repository->addNewData($requestedData);
        $user->assignRole($this->getRequestedData("role_ids") ?? []);

        return $user;
    }
}
