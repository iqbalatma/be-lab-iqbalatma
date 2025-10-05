<?php

namespace App\Http\Controllers\Management;

use App\Http\Controllers\Controller;
use App\Http\Requests\Management\Users\StoreUserRequest;
use App\Http\Requests\Management\Users\UpdateUserRequest;
use App\Services\Management\UserService;
use Iqbalatma\LaravelServiceRepo\Exceptions\DeleteDataThatStillUsedException;
use Iqbalatma\LaravelServiceRepo\Exceptions\EmptyDataException;
use Iqbalatma\LaravelUtils\APIResponse;

class UserController extends Controller
{
    public function __construct()
    {
        $this->responseMessages = [
            "index" => "Get all users successfully",
            "store" => "Add new user successfully",
            "update" => "Update user by id successfully",
            "destroy" => "Delete user by id successfully",
        ];
    }

    /**
     * @param UserService $service
     * @return APIResponse
     */
    public function index(UserService $service): APIResponse
    {
        return new APIResponse(
            $service->getAllDataPaginated(),
            $this->getResponseMessage(__FUNCTION__)
        );
    }

    /**
     * @param UserService $service
     * @param StoreUserRequest $request
     * @return APIResponse
     */
    public function store(UserService $service, StoreUserRequest $request): APIResponse
    {
        return new APIResponse(
            $service->addNewData($request->validated()),
            $this->getResponseMessage(__FUNCTION__)
        );
    }


    /**
     * @param UserService $service
     * @param UpdateUserRequest $request
     * @param string $id
     * @return APIResponse
     * @throws EmptyDataException
     */
    public function update(UserService $service, UpdateUserRequest $request, string $id): APIResponse
    {
        return new APIResponse(
            $service->updateDataById($id, $request->validated()),
            $this->getResponseMessage(__FUNCTION__)
        );
    }

    /**
     * @param UserService $service
     * @param string $id
     * @return APIResponse
     * @throws DeleteDataThatStillUsedException
     * @throws EmptyDataException
     */
    public function destroy(UserService $service, string $id): APIResponse
    {
        $service->deleteDataById($id);
        return new APIResponse(
            null,
            $this->getResponseMessage(__FUNCTION__)
        );
    }
}
