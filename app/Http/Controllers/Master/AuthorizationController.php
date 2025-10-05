<?php

namespace App\Http\Controllers\Master;

use App\Http\Controllers\Controller;
use App\Services\Master\AuthorizationService;
use Iqbalatma\LaravelUtils\APIResponse;

class AuthorizationController extends Controller
{
    public function __construct()
    {
        $this->responseMessages = [
            "roles" => "Get all roles master successfully",
            "permissions" => "Get all permissions master successfully",
        ];
    }


    /**
     * @return APIResponse
     */
    public function roles(): APIResponse
    {
        return new APIResponse(
            AuthorizationService::getAllRoles(),
            $this->getResponseMessage(__FUNCTION__)
        );
    }


    /**
     * @return APIResponse
     */
    public function permissions(): APIResponse
    {
        return new APIResponse(
            AuthorizationService::getAllPermissions(),
            $this->getResponseMessage(__FUNCTION__)
        );
    }
}
