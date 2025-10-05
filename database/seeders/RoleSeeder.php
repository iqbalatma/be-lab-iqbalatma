<?php

namespace Database\Seeders;

use App\Enums\Permission;
use App\Enums\Role;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $roles = collect();
        foreach (Role::cases() as $role){
            $createdRole = \App\Models\Role::query()->create([
                "name" => $role->value,
                "is_mutable" => false
            ]);
            $roles->push($createdRole);
        }

        /** @var \App\Models\Role $roleAdmin */
        $roleAdmin = $roles->where('name', Role::ADMIN)->first();
        $roleAdmin->givePermissionTo(Permission::values());
    }
}
