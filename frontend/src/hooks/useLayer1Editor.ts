import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { layer1API } from '../services/api'
import type { Layer1Topology } from '../types'

export const layer1EditorKeys = {
  all: ['layer1Editor'] as const,
  topology: (snapshotName: string) => [...layer1EditorKeys.all, snapshotName, 'topology'] as const,
  interfaces: (snapshotName: string) => [...layer1EditorKeys.all, snapshotName, 'interfaces'] as const,
}

export function useLayer1TopologyEditor(snapshotName: string, enabled = true) {
  return useQuery({
    queryKey: layer1EditorKeys.topology(snapshotName),
    queryFn: () => layer1API.getTopology(snapshotName),
    enabled: enabled && !!snapshotName,
    staleTime: 30000,
    retry: false,
  })
}

export function useSnapshotInterfacesList(snapshotName: string, enabled = true) {
  return useQuery({
    queryKey: layer1EditorKeys.interfaces(snapshotName),
    queryFn: () => layer1API.getInterfaces(snapshotName),
    enabled: enabled && !!snapshotName,
    staleTime: 60000,
    retry: false,
  })
}

export function useSaveLayer1TopologyEditor() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ snapshotName, topology }: { snapshotName: string; topology: Layer1Topology }) =>
      layer1API.saveTopology(snapshotName, topology),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: layer1EditorKeys.topology(variables.snapshotName) })
      queryClient.invalidateQueries({ queryKey: ['network'] })
      queryClient.refetchQueries({ queryKey: ['topology'] })
    },
  })
}

export function useDeleteLayer1TopologyEditor() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (snapshotName: string) => layer1API.deleteTopology(snapshotName),
    onSuccess: (_, snapshotName) => {
      queryClient.invalidateQueries({ queryKey: layer1EditorKeys.topology(snapshotName) })
      queryClient.invalidateQueries({ queryKey: ['network'] })
      queryClient.refetchQueries({ queryKey: ['topology'] })
    },
  })
}
