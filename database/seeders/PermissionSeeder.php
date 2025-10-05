<?php

namespace Database\Seeders;

use App\Enums\Permission;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class PermissionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        foreach (Permission::cases() as $permission) {
            \App\Models\Permission::query()->create([
                "name" => $permission->value,
                "feature" => $permission->featureGroup(),
                "description" => $permission->description(),
            ]);
        }
    }
}
