<?php

namespace App\Http\Resources\Management\Roles;

use App\Models\Permission;
use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin Role
 */
class RoleResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'is_mutable' => $this->is_mutable,
            "permissions" => $this->permissions()->get()->pluck("name"),
            "created_at" => $this->created_at->toDateTimeString(),
        ];
    }
}
