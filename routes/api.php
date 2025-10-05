<?php

use App\Http\Controllers\Auth\AuthenticateController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');


Route::prefix("auth")
    ->name("auth.")
    ->controller(AuthenticateController::class)->group(function () {
        Route::post("authenticate", "authenticate");
        Route::post("logout", "logout")->middleware("api" );
        Route::post("refresh", "refresh")->middleware("api" );
    });


Route::middleware("api")->group(function () {
    Route::prefix("master")->name("master")->group(function () {
        Route::controller(\App\Http\Controllers\Master\AuthorizationController::class)->group(function () {
            Route::get("roles", "roles")->name("roles");
            Route::get("permissions", "permissions")->name("permissions");
        });
    });


    Route::prefix("management")->name("management")->group(function () {
        Route::prefix("roles")->name("roles.")->controller(\App\Http\Controllers\Management\RoleController::class)->group(function () {
            Route::get("", "index")->name("index")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_ROLE_SHOW->value);
            Route::post("", "store")->name("store")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_ROLE_STORE->value);
            Route::patch("{id}", "update")->name("update")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_ROLE_UPDATE->value);
            Route::delete("{id}", "destroy")->name("destroy")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_ROLE_DESTROY->value);
        });

        Route::prefix("permissions")->name("permissions.")->controller(\App\Http\Controllers\Management\PermissionController::class)->group(function () {
            Route::get("", "index")->name("index")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_PERMISSION_SHOW->value);
        });

        Route::prefix("users")->name("users.")->controller(\App\Http\Controllers\Management\UserController::class)->group(function () {
            Route::get("", "index")->name("index")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_USER_SHOW->value);
            Route::post("", "store")->name("store")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_USER_STORE->value);
            Route::patch("{id}", "update")->name("update")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_USER_UPDATE->value);
            Route::delete("{id}", "destroy")->name("destroy")->middleware("permission:" . \App\Enums\Permission::MANAGEMENT_USER_DESTROY->value);
        });
    });
});
