<?php

namespace App\Http\Resources\Management\Permissions;

use App\Models\Permission;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Http\Resources\Json\ResourceCollection;

class PermissionResourceCollection extends ResourceCollection
{
    /**
     * Transform the resource collection into an array.
     *
     * @return array<int|string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->collection->transform(function (Permission|JsonResource $permission) {
            return [
                "id" => $permission->id,
                "name" => $permission->name,
                "description" => $permission->description,
                "feature" => $permission->feature,
                "created_at" => $permission->created_at->toDateTimeString(),
            ];
        })->toArray();
    }
}
