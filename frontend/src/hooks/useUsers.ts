/**
 * React Query hooks for user management and authentication
 * Handles user CRUD operations, password changes, and user listing
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { usersAPI } from '../services/api'
import type { RegisterRequest, UpdateUserRequest, ChangePasswordRequest } from '../types'

/**
 * Query key factory for user-related React Query caches
 * Hierarchical structure with list, detail, and current user (me) endpoints
 */
export const userKeys = {
  all: ['users'] as const,
  lists: () => [...userKeys.all, 'list'] as const,
  list: () => [...userKeys.all, 'list'] as const,
  details: () => [...userKeys.all, 'detail'] as const,
  detail: (id: number) => [...userKeys.details(), id] as const,
  me: () => [...userKeys.all, 'me'] as const,
}

/**
 * Query all registered users (admin only)
 * Returns complete user list with roles and status
 * Used in UserManagementPage for admin dashboard
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useUsers(enabled = true) {
  return useQuery({
    queryKey: userKeys.list(),
    queryFn: () => usersAPI.list(),
    enabled,
    staleTime: 30000, // 30 seconds
  })
}

/**
 * Query specific user by ID (admin only)
 * Returns user details for editing in UserEditPage
 * @param id - User ID to fetch
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useUser(id: number, enabled = true) {
  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: () => usersAPI.getById(id),
    enabled: enabled && !!id,
    staleTime: 30000, // 30 seconds
  })
}

/**
 * Query current authenticated user profile
 * Returns own user data for ProfilePage and auth state
 * Does not retry on 401 to avoid infinite loops during logout
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useCurrentUser(enabled = true) {
  return useQuery({
    queryKey: userKeys.me(),
    queryFn: () => usersAPI.getMe(),
    enabled,
    staleTime: 60000, // 60 seconds
    retry: false, // Don't retry on 401
  })
}

/**
 * Mutation to register new user account
 * Creates user and invalidates user list cache for admin dashboard
 * Used in RegisterPage for self-registration
 */
export function useRegister() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: RegisterRequest) => usersAPI.register(data),
    onSuccess: () => {
      // Invalidate users list (admin view)
      queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

/**
 * Mutation to update user profile (admin or self)
 * Updates email, full name, roles, and active status
 * Invalidates all related caches: detail, list, and me
 * Used in ProfilePage (self) and UserEditPage (admin)
 */
export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdateUserRequest }) =>
      usersAPI.update(id, data),
    onSuccess: (_, variables) => {
      // Invalidate specific user detail
      queryClient.invalidateQueries({ queryKey: userKeys.detail(variables.id) })
      // Invalidate users list
      queryClient.invalidateQueries({ queryKey: userKeys.list() })
      // Invalidate current user if updating self
      queryClient.invalidateQueries({ queryKey: userKeys.me() })
    },
  })
}

/**
 * Mutation to change user password
 * Requires current password verification
 * No cache invalidation needed as password not cached
 * Used in PasswordChangeForm component
 */
export function useChangePassword() {
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: ChangePasswordRequest }) =>
      usersAPI.changePassword(id, data),
    // No cache invalidation needed for password change
  })
}

/**
 * Mutation to delete user account (admin only)
 * Removes user from system and invalidates caches
 * Users cannot delete themselves (enforced in UI and backend)
 * Used in UserManagementPage with confirmation dialog
 */
export function useDeleteUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: number) => usersAPI.delete(id),
    onSuccess: (_, id) => {
      // Remove specific user from cache
      queryClient.removeQueries({ queryKey: userKeys.detail(id) })
      // Invalidate users list
      queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}
