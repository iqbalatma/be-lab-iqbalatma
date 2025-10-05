<?php

namespace App\Http\Controllers\Management;

use App\Events\RoleChangedEvent;
use App\Exceptions\InvalidActionException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Management\Roles\StoreRoleRequest;
use App\Http\Requests\Management\Roles\UpdateRoleRequest;
use App\Http\Resources\Management\Roles\RoleResource;
use App\Http\Resources\Management\Roles\RoleResourceCollection;
use App\Services\Management\RoleService;
use Iqbalatma\LaravelServiceRepo\Exceptions\DeleteDataThatStillUsedException;
use Iqbalatma\LaravelServiceRepo\Exceptions\EmptyDataException;
use Iqbalatma\LaravelUtils\APIResponse;

class RoleController extends Controller
{
    public function __construct()
    {
        $this->responseMessages = [
            "index" => "Get all roles successfully",
            "store" => "Add new role successfully",
            "update" => "Update role by id successfully",
            "destroy" => "Delete role by id successfully",
        ];
    }

    /**
     * @return APIResponse
     */
    public function index(): APIResponse
    {
        return new APIResponse(
            new RoleResourceCollection(RoleService::getAllCachedData()),
            $this->getResponseMessage(__FUNCTION__)
        );
    }

    /**
     * @param RoleService $service
     * @param StoreRoleRequest $request
     * @return APIResponse
     */
    public function store(RoleService $service, StoreRoleRequest $request): APIResponse
    {
        RoleChangedEvent::dispatch();
        return new APIResponse(
            new RoleResource($service->addNewData($request->validated())),
            $this->getResponseMessage(__FUNCTION__)
        );
    }


    /**
     * @param RoleService $service
     * @param UpdateRoleRequest $request
     * @param string $id
     * @return APIResponse
     * @throws EmptyDataException
     */
    public function update(RoleService $service, UpdateRoleRequest $request, string $id): APIResponse
    {
        RoleChangedEvent::dispatch();
        return new APIResponse(
            new RoleResource($service->updateDataById($id, $request->validated())),
            $this->getResponseMessage(__FUNCTION__)
        );
    }

    /**
     * @param RoleService $service
     * @param string $id
     * @return APIResponse
     * @throws DeleteDataThatStillUsedException
     * @throws EmptyDataException|InvalidActionException
     */
    public function destroy(RoleService $service, string $id): APIResponse
    {
        $service->deleteDataById($id);
        RoleChangedEvent::dispatch();
        return new APIResponse(
            null,
            $this->getResponseMessage(__FUNCTION__)
        );
    }
}
