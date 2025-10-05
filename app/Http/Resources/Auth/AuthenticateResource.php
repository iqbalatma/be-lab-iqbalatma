<?php

namespace App\Http\Resources\Auth;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin User */
class AuthenticateResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $user = $this["user"];
        return [
            "id" => $user->id,
            "email" => $user->email,
            "username" => $user->username,
            "name" => $user->name,
            "roles" => $user->roles->pluck("name"),
            "permissions" => $user->getPermissionsViaRoles()->unique('name')->pluck('name'),
            "access_token" => $this["tokens"]["access_token"],
            "refresh_token" => $this["tokens"]["refresh_token"],
            "created_at" => Carbon::parse($user->created_at)->toDateTimeString(),
            "updated_at" => Carbon::parse($user->updated_at)->toDateTimeString(),
        ];
    }
}
