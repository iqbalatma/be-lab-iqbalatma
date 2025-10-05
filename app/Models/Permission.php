<?php

namespace App\Models;

use App\Enums\Table;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string id
 * @property string name
 * @property string feature
 * @property string guard_name
 * @property string description
 * @property Carbon created_at
 * @property Carbon updated_at
 */
class Permission extends \Spatie\Permission\Models\Permission
{
    use HasUuids;

    protected $table = Table::permissions->name;
    protected $fillable = [
        "name", "feature", "guard_name", "description"
    ];
}
