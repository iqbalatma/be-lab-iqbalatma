<?php

namespace App\Http\Controllers\Management;

use App\Http\Controllers\Controller;
use App\Http\Resources\Management\Permissions\PermissionResourceCollection;
use App\Services\Management\PermissionService;
use Illuminate\Http\Request;
use Iqbalatma\LaravelUtils\APIResponse;

class PermissionController extends Controller
{
    public function __construct()
    {
        $this->responseMessages = [
            "index" => "Get all permissions successfully",
        ];
    }


    /**
     * @return APIResponse
     */
    public function index(): APIResponse
    {
        return new APIResponse(
            new PermissionResourceCollection(PermissionService::getAllDataCached()),
            $this->getResponseMessage(__FUNCTION__)
        );
    }
}
