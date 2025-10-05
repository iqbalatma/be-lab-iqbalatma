<?php

namespace App\Http\Resources\Management\Roles;

use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Http\Resources\Json\ResourceCollection;

class RoleResourceCollection extends ResourceCollection
{
    /**
     * Transform the resource collection into an array.
     *
     * @return array<int|string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->collection->transform(function (Role|JsonResource $role) {
            return [
                'id' => $role->id,
                'name' => $role->name,
                'is_mutable' => $role->is_mutable,
                "created_at" => $role->created_at->toDateTimeString(),
            ];
        })->toArray($request);
    }
}
