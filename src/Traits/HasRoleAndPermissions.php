<?php

namespace SharedRolePermission\Shared\Traits;

use Illuminate\Database\Eloquent\Builder;
use App\Enums\{UserRole, Permissions};

trait HasRoleAndPermissions
{
     /**
     * Optionally: check if user has a specific role
     */
    public function hasRole(UserRole|string $role): bool
    {
        $roleValue = $role instanceof UserRole ? $role->value : $role;
        
        return $this->role === $roleValue;
    }

     /**
     * Optionally: check if user has any of role
     */
    public function hasAnyRole(array $roles): bool
    {
        return in_array($this->role, $roles);
    }

    /**
     * Check if user has the given permission(s)
     *
     * @param string|array $permissions Single or multiple permission keys
     * @param bool $requireAll True = all permissions required (AND), False = any permission (OR) user has ALL permission
     * @return bool
     */
    public function hasPermission(string|array $permissions, bool $requireAll = false): bool
    {
        $userRolePermissions = $this->getUserRolePermissions();
        $permissions = (array) $permissions;
        $rolePermissions = $userRolePermissions[$this->role] ?? [];

        if ($requireAll) {
            return empty(array_diff($permissions, $rolePermissions));
        } else {
            return (bool) array_intersect($permissions, $rolePermissions) || in_array('all', $rolePermissions);
        }
    }

    // Combined user-role permissions
    public function getUserRolePermissions(): array
    {
        return [
            UserRole::DOCTOR->value => [
                Permissions::ALL->value
            ],
            UserRole::SUPER_ADMIN->value => [
                Permissions::ALL->value
            ],
            UserRole::PATIENT->value => [
                Permissions::VIEW_PATIENT->value,
                Permissions::UPDATE_PATIENT->value,
                Permissions::VIEW_PATIENT_MEDICAL_HISTORY->value,
                Permissions::VIEW_APPOINTMENT->value,
                Permissions::SCHEDULE_APPOINTMENT->value,
                Permissions::UPDATE_APPOINTMENT->value,
                Permissions::DELETE_APPOINTMENT->value,
                Permissions::VIEW_PROFILE->value,
                Permissions::UPDATE_PROFILE->value,
            ],
            UserRole::STAFF->value => [
                Permissions::VIEW_PATIENT->value,
                Permissions::UPDATE_PATIENT->value,
                Permissions::VIEW_PATIENT_MEDICAL_HISTORY->value,
                Permissions::VIEW_APPOINTMENT->value,
                Permissions::SCHEDULE_APPOINTMENT->value,
                Permissions::UPDATE_APPOINTMENT->value,
                Permissions::DELETE_APPOINTMENT->value,
                Permissions::VIEW_PROFILE->value,
                Permissions::UPDATE_PROFILE->value,
                Permissions::VIEW_DASHBOARD->value,
            ],
        ];
    }

    
    // Mutators
    public function getPermissionsAttribute(): array
    {
        return $this->getUserRolePermissions()[$this->role];
    }
}
