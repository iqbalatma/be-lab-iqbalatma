<?php

namespace App\Enums;

use App\Enums\MetaProperties\Description;
use App\Enums\MetaProperties\FeatureGroup;
use ArchTech\Enums\Meta\Meta;
use ArchTech\Enums\Metadata;
use ArchTech\Enums\Values;

/**
 * @method featureGroup
 * @method description
 */
#[Meta(Description::class, FeatureGroup::class)]
enum Permission: string
{
    use Metadata, Values;

    #[Description("can show data permission")] #[FeatureGroup("management - permission")]
    case MANAGEMENT_PERMISSION_SHOW = "management.permission.show";

    #[Description("can show data role")] #[FeatureGroup("management - role")]
    case MANAGEMENT_ROLE_SHOW = "management.role.show";
    #[Description("can add new data role")] #[FeatureGroup("management - role")]
    case MANAGEMENT_ROLE_STORE = "management.role.store";
    #[Description("can update data role")] #[FeatureGroup("management - role")]
    case MANAGEMENT_ROLE_UPDATE = "management.role.update";
    #[Description("can delete data role")] #[FeatureGroup("management - role")]
    case MANAGEMENT_ROLE_DESTROY = "management.role.destroy";

    #[Description("can show data user")] #[FeatureGroup("management - user")]
    case MANAGEMENT_USER_SHOW = "management.user.show";
    #[Description("can add new data user")] #[FeatureGroup("management - user")]
    case MANAGEMENT_USER_STORE = "management.user.store";
    #[Description("can update data user")] #[FeatureGroup("management - user")]
    case MANAGEMENT_USER_UPDATE = "management.user.update";
    #[Description("can delete data user")] #[FeatureGroup("management - user")]
    case MANAGEMENT_USER_DESTROY = "management.user.destroy";
}
