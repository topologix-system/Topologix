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
  details: () => [...userKeys.all, 'detail'] as const,
  detail: (id: number) => [...userKeys.details(), id] as const,
  me: () => [...userKeys.all, 'me'] as const,
}

/**
 * Query all registered users (admin only)
 * Returns complete user list with roles and status
 */
export function useUsers(enabled = true) {
  return useQuery({
    queryKey: userKeys.lists(),
    queryFn: () => usersAPI.list(),
    enabled,
    staleTime: 30000,
  })
}

/**
 * Query specific user by ID (admin only)
 */
export function useUser(id: number, enabled = true) {
  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: () => usersAPI.getById(id),
    enabled: enabled && !!id,
    staleTime: 30000,
  })
}

/**
 * Query current authenticated user profile
 */
export function useCurrentUser(enabled = true) {
  return useQuery({
    queryKey: userKeys.me(),
    queryFn: () => usersAPI.getMe(),
    enabled,
    staleTime: 60000,
    retry: false,
  })
}

/**
 * Mutation to register new user account
 */
export function useRegister() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: RegisterRequest) => usersAPI.register(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
    },
  })
}

/**
 * Mutation to update user profile (admin or self)
 * Updates email, full name, roles, and active status
 */
export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdateUserRequest }) =>
      usersAPI.update(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(variables.id) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      queryClient.invalidateQueries({ queryKey: userKeys.me() })
    },
  })
}

/**
 * Mutation to change user password
 * Requires current password verification
 */
export function useChangePassword() {
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: ChangePasswordRequest }) =>
      usersAPI.changePassword(id, data),
  })
}

/**
 * Mutation to delete user account (admin only)
 * Removes user from system and invalidates caches
 */
export function useDeleteUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: number) => usersAPI.delete(id),
    onSuccess: (_, id) => {
      queryClient.removeQueries({ queryKey: userKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
    },
  })
}
