import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  GitCompare,
  GitBranch,
  Layers,
  Network,
  Play,
  Search,
  Server,
} from 'lucide-react'
import {
  useA10VirtualServerConfiguration,
  useBidirectionalReachability,
  useCompareFilters,
  useComparePeerGroupPolicies,
  useCompareRoutePolicies,
  useLpmRoutes,
  usePrefixTracer,
  useResolveFilterSpecifier,
  useResolveInterfaceSpecifier,
  useResolveIpSpecifier,
  useResolveIpsOfLocationSpecifier,
  useResolveLocationSpecifier,
  useResolveNodeSpecifier,
  useSearchRoutePolicies,
  useSnapshots,
  useTestRoutePolicies,
  useTransferBDDValidation,
  useUserProvidedLayer1Edges,
} from '../../hooks'

type MutationLike = {
  data?: unknown
  error?: unknown
  isError: boolean
  isPending: boolean
  isSuccess: boolean
}

type ResultLabels = {
  resultPrefix: string
  running: string
  runningText: string
  error: string
  noData: string
  done: string
}

type ValidationError = {
  key: string
  fieldKey?: string
}

type ValidationMessages = {
  jsonObject: (fieldKey: string) => ValidationError
  invalidJson: (fieldKey: string) => ValidationError
  inputRoutesRequired: ValidationError
  inputRoutesType: ValidationError
  inputRoutesInvalidJson: ValidationError
  integerField: (fieldKey: string) => ValidationError
}

type OptionItem<T extends string> = {
  value: T
  label: string
  icon?: ReactNode
  description?: string
}

type ToolCategory = 'resolve' | 'filters' | 'policies' | 'edge'
type FilterTool = 'compare' | 'lpm' | 'prefix' | 'bidirectional'
type PolicyTool = 'search' | 'test' | 'transfer' | 'compare'
type EdgeTool = 'a10' | 'layer1'
type ResultKey =
  | 'resolveNodes'
  | 'resolveFilters'
  | 'resolveInterfaces'
  | 'resolveLocations'
  | 'resolveIps'
  | 'resolveIpsOfLocation'
  | 'compareFilters'
  | 'lpmRoutes'
  | 'prefixTracer'
  | 'bidirectionalReachability'
  | 'searchRoutePolicies'
  | 'testRoutePolicies'
  | 'transferBDD'
  | 'compareRoutePolicies'
  | 'comparePeerGroups'
  | 'a10VirtualServers'
  | 'userLayer1Edges'

function parseJsonObject(value: string, fieldKey: string, messages: ValidationMessages): { value?: object; error?: ValidationError } {
  if (!value.trim()) {
    return {}
  }

  try {
    const parsed = JSON.parse(value)
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
      return { error: messages.jsonObject(fieldKey) }
    }
    return { value: parsed }
  } catch {
    return { error: messages.invalidJson(fieldKey) }
  }
}

function parseJsonRouteList(value: string, messages: ValidationMessages): { value?: object | object[]; error?: ValidationError } {
  if (!value.trim()) {
    return { error: messages.inputRoutesRequired }
  }

  try {
    const parsed = JSON.parse(value)
    if (Array.isArray(parsed)) {
      return { value: parsed }
    }
    if (parsed !== null && typeof parsed === 'object') {
      return { value: parsed }
    }
    return { error: messages.inputRoutesType }
  } catch {
    return { error: messages.inputRoutesInvalidJson }
  }
}

function parseIntegerString(value: string, fieldKey: string, messages: ValidationMessages): { value?: string; error?: ValidationError } {
  const trimmed = value.trim()
  if (!trimmed) {
    return {}
  }
  if (!/^-?\d+$/.test(trimmed)) {
    return { error: messages.integerField(fieldKey) }
  }
  return { value: trimmed }
}

function ResultBlock({ title, mutation, labels }: { title: string; mutation: MutationLike; labels: ResultLabels }) {
  const hasData = mutation.data !== undefined && mutation.data !== null && (
    Array.isArray(mutation.data)
      ? mutation.data.length > 0
      : typeof mutation.data === 'object'
        ? Object.keys(mutation.data as Record<string, unknown>).length > 0
        : String(mutation.data).length > 0
  )

  if (mutation.isPending) {
    return (
      <section className="border-t border-gray-100 pt-4">
        <div className="mb-2 flex items-center justify-between gap-2">
          <h4 className="text-sm font-semibold text-gray-900">{labels.resultPrefix}: {title}</h4>
          <span className="rounded-full bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-700">{labels.running}</span>
        </div>
        <p className="text-sm text-gray-600">{labels.runningText}</p>
      </section>
    )
  }

  if (mutation.isError) {
    return (
      <section className="border-t border-gray-100 pt-4">
        <div className="mb-2 flex items-center justify-between gap-2">
          <h4 className="text-sm font-semibold text-gray-900">{labels.resultPrefix}: {title}</h4>
          <span className="rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700">{labels.error}</span>
        </div>
        <p className="text-sm text-red-600">{String(mutation.error)}</p>
      </section>
    )
  }

  if (!mutation.isSuccess) {
    return null
  }

  if (!hasData) {
    return (
      <section className="border-t border-gray-100 pt-4">
        <div className="mb-2 flex items-center justify-between gap-2">
          <h4 className="text-sm font-semibold text-gray-900">{labels.resultPrefix}: {title}</h4>
          <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700">{labels.noData}</span>
        </div>
        <p className="text-sm text-gray-600">{labels.noData}</p>
      </section>
    )
  }

  return (
    <section className="border-t border-gray-100 pt-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-gray-900">{labels.resultPrefix}: {title}</h4>
        <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">{labels.done}</span>
      </div>
      <div className="max-h-80 overflow-y-auto">
        <pre className="overflow-x-auto rounded bg-gray-50 p-3 text-xs">
          {JSON.stringify(mutation.data, null, 2)}
        </pre>
      </div>
    </section>
  )
}

function SegmentedControl<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string
  options: Array<OptionItem<T>>
  value: T
  onChange: (value: T) => void
}) {
  return (
    <div className="flex flex-wrap gap-1 rounded-lg border border-gray-200 bg-gray-50 p-1" aria-label={label}>
      {options.map((option) => {
        const selected = option.value === value
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={selected}
            title={option.description}
            className={`inline-flex min-h-[2.25rem] min-w-[7rem] flex-1 items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-center text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 ${
              selected
                ? 'border-gray-200 bg-white text-primary-700 shadow-sm'
                : 'border-transparent text-gray-600 hover:bg-white/70 hover:text-gray-900'
            }`}
            onClick={() => onChange(option.value)}
          >
            {option.icon}
            {option.label}
          </button>
        )
      })}
    </div>
  )
}

function SectionIntro({ icon, title, description }: { icon: ReactNode; title: string; description: string }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        {icon}
        <h4 className="text-sm font-semibold text-gray-900">{title}</h4>
      </div>
      <p className="text-xs leading-5 text-gray-600">{description}</p>
    </div>
  )
}

function OperationDescription({ description }: { description: string }) {
  return <p className="text-xs leading-5 text-gray-600">{description}</p>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-xs font-medium text-gray-700">
      <span className="mb-1 block">{label}</span>
      {children}
    </label>
  )
}

const textInputClass = 'w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-600'
const textareaClass = 'w-full px-3 py-1.5 text-sm font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-600'
const buttonClass = 'inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 text-white rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1'
const checkboxActionRowClass = 'flex flex-col gap-4 pt-2 sm:flex-row sm:items-center sm:justify-between'
const checkboxLabelClass = 'inline-flex min-h-[2.25rem] items-center gap-2 text-xs text-gray-700'

export function BatfishFeatureTools() {
  const { t } = useTranslation()
  const snapshots = useSnapshots()
  const resolveFilters = useResolveFilterSpecifier()
  const resolveNodes = useResolveNodeSpecifier()
  const resolveInterfaces = useResolveInterfaceSpecifier()
  const compareFilters = useCompareFilters()
  const resolveLocations = useResolveLocationSpecifier()
  const resolveIps = useResolveIpSpecifier()
  const resolveIpsOfLocation = useResolveIpsOfLocationSpecifier()
  const lpmRoutes = useLpmRoutes()
  const prefixTracer = usePrefixTracer()
  const bidirectionalReachability = useBidirectionalReachability()
  const searchRoutePolicies = useSearchRoutePolicies()
  const testRoutePolicies = useTestRoutePolicies()
  const transferBDD = useTransferBDDValidation()
  const comparePeerGroups = useComparePeerGroupPolicies()
  const compareRoutePolicies = useCompareRoutePolicies()
  const a10VirtualServers = useA10VirtualServerConfiguration()
  const userLayer1Edges = useUserProvidedLayer1Edges()

  const [specifierNodes, setSpecifierNodes] = useState('')
  const [specifierFilters, setSpecifierFilters] = useState('')
  const [specifierInterfaces, setSpecifierInterfaces] = useState('')
  const [locations, setLocations] = useState('')
  const [ips, setIps] = useState('')
  const [grammarVersion, setGrammarVersion] = useState('')
  const [compareReferenceSnapshot, setCompareReferenceSnapshot] = useState('')
  const [compareSnapshot, setCompareSnapshot] = useState('')
  const [compareFilterNames, setCompareFilterNames] = useState('')
  const [compareFilterNodes, setCompareFilterNodes] = useState('')
  const [ignoreComposites, setIgnoreComposites] = useState(false)

  const [lpmIp, setLpmIp] = useState('')
  const [lpmNodes, setLpmNodes] = useState('')
  const [lpmVrfs, setLpmVrfs] = useState('')
  const [prefix, setPrefix] = useState('')
  const [prefixNodes, setPrefixNodes] = useState('')
  const [bidirectionalHeaders, setBidirectionalHeaders] = useState('')
  const [bidirectionalPathConstraints, setBidirectionalPathConstraints] = useState('')
  const [returnFlowType, setReturnFlowType] = useState('SUCCESS')

  const [routePolicyAction, setRoutePolicyAction] = useState('permit')
  const [routePolicyNodes, setRoutePolicyNodes] = useState('')
  const [routePolicyPolicies, setRoutePolicyPolicies] = useState('')
  const [inputConstraints, setInputConstraints] = useState('')
  const [outputConstraints, setOutputConstraints] = useState('')
  const [perPath, setPerPath] = useState(false)
  const [pathOption, setPathOption] = useState('')
  const [testDirection, setTestDirection] = useState('IN')
  const [testInputRoutes, setTestInputRoutes] = useState('')
  const [testNodes, setTestNodes] = useState('')
  const [testPolicies, setTestPolicies] = useState('')
  const [transferNodes, setTransferNodes] = useState('')
  const [transferPolicies, setTransferPolicies] = useState('')
  const [retainAllPaths, setRetainAllPaths] = useState(false)
  const [transferSeed, setTransferSeed] = useState('')
  const [routeCompareReferenceSnapshot, setRouteCompareReferenceSnapshot] = useState('')
  const [routeCompareSnapshot, setRouteCompareSnapshot] = useState('')
  const [comparePolicy, setComparePolicy] = useState('')
  const [referencePolicy, setReferencePolicy] = useState('')
  const [compareRouteNodes, setCompareRouteNodes] = useState('')

  const [a10Nodes, setA10Nodes] = useState('')
  const [a10VirtualServerIps, setA10VirtualServerIps] = useState('')
  const [layer1Nodes, setLayer1Nodes] = useState('')
  const [layer1RemoteNodes, setLayer1RemoteNodes] = useState('')
  const [formError, setFormError] = useState<ValidationError | null>(null)
  const [activeCategory, setActiveCategory] = useState<ToolCategory>('resolve')
  const [activeFilterTool, setActiveFilterTool] = useState<FilterTool>('compare')
  const [activePolicyTool, setActivePolicyTool] = useState<PolicyTool>('search')
  const [activeEdgeTool, setActiveEdgeTool] = useState<EdgeTool>('a10')
  const [activeResult, setActiveResult] = useState<ResultKey | null>(null)

  const snapshotOptions = snapshots.data?.map((snapshot) => snapshot.name) ?? []
  const categoryOptions: Array<OptionItem<ToolCategory>> = [
    { value: 'resolve', label: t('batfishTools.categories.resolve'), description: t('batfishTools.categoryDescriptions.resolve'), icon: <Search className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'filters', label: t('batfishTools.categories.filters'), description: t('batfishTools.categoryDescriptions.filters'), icon: <Network className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'policies', label: t('batfishTools.categories.policies'), description: t('batfishTools.categoryDescriptions.policies'), icon: <GitBranch className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'edge', label: t('batfishTools.categories.edge'), description: t('batfishTools.categoryDescriptions.edge'), icon: <Server className="h-3.5 w-3.5" aria-hidden="true" /> },
  ]
  const filterToolOptions: Array<OptionItem<FilterTool>> = [
    { value: 'compare', label: t('batfishTools.operations.filters.compare'), description: t('batfishTools.operationDescriptions.filters.compare'), icon: <GitCompare className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'lpm', label: t('batfishTools.operations.filters.lpm'), description: t('batfishTools.operationDescriptions.filters.lpm'), icon: <Play className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'prefix', label: t('batfishTools.operations.filters.prefix'), description: t('batfishTools.operationDescriptions.filters.prefix'), icon: <Search className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'bidirectional', label: t('batfishTools.operations.filters.bidirectional'), description: t('batfishTools.operationDescriptions.filters.bidirectional'), icon: <Network className="h-3.5 w-3.5" aria-hidden="true" /> },
  ]
  const policyToolOptions: Array<OptionItem<PolicyTool>> = [
    { value: 'search', label: t('batfishTools.operations.policies.search'), description: t('batfishTools.operationDescriptions.policies.search'), icon: <Search className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'test', label: t('batfishTools.operations.policies.test'), description: t('batfishTools.operationDescriptions.policies.test'), icon: <Play className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'transfer', label: t('batfishTools.operations.policies.transfer'), description: t('batfishTools.operationDescriptions.policies.transfer'), icon: <Activity className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'compare', label: t('batfishTools.operations.policies.compare'), description: t('batfishTools.operationDescriptions.policies.compare'), icon: <GitCompare className="h-3.5 w-3.5" aria-hidden="true" /> },
  ]
  const edgeToolOptions: Array<OptionItem<EdgeTool>> = [
    { value: 'a10', label: t('batfishTools.operations.edge.a10'), description: t('batfishTools.operationDescriptions.edge.a10'), icon: <Server className="h-3.5 w-3.5" aria-hidden="true" /> },
    { value: 'layer1', label: t('batfishTools.operations.edge.layer1'), description: t('batfishTools.operationDescriptions.edge.layer1'), icon: <Layers className="h-3.5 w-3.5" aria-hidden="true" /> },
  ]

  const resultMap: Record<ResultKey, { title: string; mutation: MutationLike }> = {
    resolveNodes: { title: t('batfishTools.results.resolveNodes'), mutation: resolveNodes },
    resolveFilters: { title: t('batfishTools.results.resolveFilters'), mutation: resolveFilters },
    resolveInterfaces: { title: t('batfishTools.results.resolveInterfaces'), mutation: resolveInterfaces },
    resolveLocations: { title: t('batfishTools.results.resolveLocations'), mutation: resolveLocations },
    resolveIps: { title: t('batfishTools.results.resolveIps'), mutation: resolveIps },
    resolveIpsOfLocation: { title: t('batfishTools.results.resolveIpsOfLocation'), mutation: resolveIpsOfLocation },
    compareFilters: { title: t('batfishTools.results.compareFilters'), mutation: compareFilters },
    lpmRoutes: { title: t('batfishTools.results.lpmRoutes'), mutation: lpmRoutes },
    prefixTracer: { title: t('batfishTools.results.prefixTracer'), mutation: prefixTracer },
    bidirectionalReachability: { title: t('batfishTools.results.bidirectionalReachability'), mutation: bidirectionalReachability },
    searchRoutePolicies: { title: t('batfishTools.results.searchRoutePolicies'), mutation: searchRoutePolicies },
    testRoutePolicies: { title: t('batfishTools.results.testRoutePolicies'), mutation: testRoutePolicies },
    transferBDD: { title: t('batfishTools.results.transferBDD'), mutation: transferBDD },
    compareRoutePolicies: { title: t('batfishTools.results.compareRoutePolicies'), mutation: compareRoutePolicies },
    comparePeerGroups: { title: t('batfishTools.results.comparePeerGroups'), mutation: comparePeerGroups },
    a10VirtualServers: { title: t('batfishTools.results.a10VirtualServers'), mutation: a10VirtualServers },
    userLayer1Edges: { title: t('batfishTools.results.userLayer1Edges'), mutation: userLayer1Edges },
  }
  const activeResultView = activeResult ? resultMap[activeResult] : null
  const resultLabels: ResultLabels = {
    resultPrefix: t('batfishTools.resultStatus.result'),
    running: t('batfishTools.resultStatus.running'),
    runningText: t('batfishTools.resultStatus.runningText'),
    error: t('batfishTools.resultStatus.error'),
    noData: t('batfishTools.resultStatus.noData'),
    done: t('batfishTools.resultStatus.done'),
  }
  const validationMessages: ValidationMessages = {
    jsonObject: (fieldKey) => ({ key: 'batfishTools.errors.jsonObject', fieldKey }),
    invalidJson: (fieldKey) => ({ key: 'batfishTools.errors.invalidJson', fieldKey }),
    inputRoutesRequired: { key: 'batfishTools.errors.inputRoutesRequired' },
    inputRoutesType: { key: 'batfishTools.errors.inputRoutesType' },
    inputRoutesInvalidJson: { key: 'batfishTools.errors.inputRoutesInvalidJson' },
    integerField: (fieldKey) => ({ key: 'batfishTools.errors.integerField', fieldKey }),
  }
  const resolveDescriptions = [
    { label: t('batfishTools.buttons.nodes'), description: t('batfishTools.resolveDescriptions.nodes') },
    { label: t('batfishTools.buttons.filters'), description: t('batfishTools.resolveDescriptions.filters') },
    { label: t('batfishTools.buttons.interfaces'), description: t('batfishTools.resolveDescriptions.interfaces') },
    { label: t('batfishTools.buttons.locations'), description: t('batfishTools.resolveDescriptions.locations') },
    { label: t('batfishTools.buttons.ips'), description: t('batfishTools.resolveDescriptions.ips') },
    { label: t('batfishTools.buttons.locationIps'), description: t('batfishTools.resolveDescriptions.locationIps') },
  ]

  const selectCategory = (category: ToolCategory) => {
    setFormError(null)
    setActiveCategory(category)
  }

  const selectFilterTool = (tool: FilterTool) => {
    setFormError(null)
    setActiveFilterTool(tool)
  }

  const selectPolicyTool = (tool: PolicyTool) => {
    setFormError(null)
    setActivePolicyTool(tool)
  }

  const selectEdgeTool = (tool: EdgeTool) => {
    setFormError(null)
    setActiveEdgeTool(tool)
  }

  const runWithResult = (result: ResultKey, action: () => void) => {
    setFormError(null)
    setActiveResult(result)
    action()
  }

  const runSearchRoutePolicies = () => {
    const input = parseJsonObject(inputConstraints, 'batfishTools.fields.inputConstraintsJson', validationMessages)
    const output = parseJsonObject(outputConstraints, 'batfishTools.fields.outputConstraintsJson', validationMessages)
    if (input.error || output.error) {
      setFormError(input.error || output.error || null)
      return
    }
    setFormError(null)
    setActiveResult('searchRoutePolicies')
    searchRoutePolicies.mutate({
      action: routePolicyAction || undefined,
      nodes: routePolicyNodes.trim() || undefined,
      policies: routePolicyPolicies.trim() || undefined,
      inputConstraints: input.value,
      outputConstraints: output.value,
      perPath,
      pathOption: pathOption.trim() || undefined,
    })
  }

  const runTestRoutePolicies = () => {
    const inputRoutes = parseJsonRouteList(testInputRoutes, validationMessages)
    if (inputRoutes.error) {
      setFormError(inputRoutes.error)
      return
    }
    setFormError(null)
    setActiveResult('testRoutePolicies')
    testRoutePolicies.mutate({
      direction: testDirection,
      inputRoutes: inputRoutes.value as object | object[],
      nodes: testNodes.trim() || undefined,
      policies: testPolicies.trim() || undefined,
    })
  }

  const runBidirectionalReachability = () => {
    const headers = parseJsonObject(bidirectionalHeaders, 'batfishTools.fields.bidirectionalHeadersJson', validationMessages)
    const pathConstraints = parseJsonObject(bidirectionalPathConstraints, 'batfishTools.fields.pathConstraintsJson', validationMessages)
    if (headers.error || pathConstraints.error) {
      setFormError(headers.error || pathConstraints.error || null)
      return
    }
    if (!headers.value) {
      setFormError({ key: 'batfishTools.errors.headersRequired' })
      return
    }
    setFormError(null)
    setActiveResult('bidirectionalReachability')
    bidirectionalReachability.mutate({
      headers: headers.value,
      pathConstraints: pathConstraints.value,
      returnFlowType: returnFlowType.trim() || undefined,
    })
  }

  const runTransferBDDValidation = () => {
    const seed = parseIntegerString(transferSeed, 'batfishTools.fields.seed', validationMessages)
    if (seed.error) {
      setFormError(seed.error)
      return
    }

    setFormError(null)
    setActiveResult('transferBDD')
    transferBDD.mutate({
      nodes: transferNodes || undefined,
      policies: transferPolicies || undefined,
      retainAllPaths,
      seed: seed.value,
    })
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white shadow-sm">
      <div className="flex items-center gap-2 border-b border-gray-200 px-4 py-3">
        <Activity className="h-5 w-5 text-primary-600" aria-hidden="true" />
        <h3 className="text-base font-semibold text-gray-900">{t('batfishTools.title')}</h3>
      </div>

      <div className="border-b border-gray-100 bg-gray-50/70 px-4 py-3">
        <SegmentedControl
          label={t('batfishTools.categoryLabel')}
          options={categoryOptions}
          value={activeCategory}
          onChange={selectCategory}
        />
      </div>

      <div className="space-y-4 p-4">
        {formError && (
          <p className="text-sm text-red-600">
            {t(formError.key, formError.fieldKey ? { field: t(formError.fieldKey) } : undefined)}
          </p>
        )}

        {activeCategory === 'resolve' && (
          <section className="space-y-3" aria-label={t('batfishTools.sections.specifierResolution')}>
            <SectionIntro
              icon={<Search className="h-4 w-4 text-primary-600" aria-hidden="true" />}
              title={t('batfishTools.sections.specifierResolution')}
              description={t('batfishTools.categoryDescriptions.resolve')}
            />
            <div className="grid gap-3 md:grid-cols-2">
              <Field label={t('batfishTools.fields.nodes')}>
                <input className={textInputClass} value={specifierNodes} onChange={(event) => setSpecifierNodes(event.target.value)} />
              </Field>
              <Field label={t('batfishTools.fields.grammarVersion')}>
                <input className={textInputClass} value={grammarVersion} onChange={(event) => setGrammarVersion(event.target.value)} />
              </Field>
              <Field label={t('batfishTools.fields.filters')}>
                <input className={textInputClass} value={specifierFilters} onChange={(event) => setSpecifierFilters(event.target.value)} />
              </Field>
              <Field label={t('batfishTools.fields.interfaces')}>
                <input className={textInputClass} value={specifierInterfaces} onChange={(event) => setSpecifierInterfaces(event.target.value)} />
              </Field>
              <Field label={t('batfishTools.fields.locations')}>
                <input className={textInputClass} value={locations} onChange={(event) => setLocations(event.target.value)} />
              </Field>
              <Field label={t('batfishTools.fields.ips')}>
                <input className={textInputClass} value={ips} onChange={(event) => setIps(event.target.value)} />
              </Field>
            </div>
            <div className="grid gap-2 text-xs leading-5 text-gray-600 md:grid-cols-2">
              {resolveDescriptions.map((item) => (
                <p key={item.label}>
                  <span className="font-medium text-gray-800">{item.label}:</span> {item.description}
                </p>
              ))}
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" className={buttonClass} disabled={resolveNodes.isPending || !specifierNodes.trim()} onClick={() => runWithResult('resolveNodes', () => resolveNodes.mutate({ nodes: specifierNodes || undefined, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.nodes')}
              </button>
              <button type="button" className={buttonClass} disabled={resolveFilters.isPending || !specifierFilters.trim()} onClick={() => runWithResult('resolveFilters', () => resolveFilters.mutate({ filters: specifierFilters || undefined, nodes: specifierNodes || undefined, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.filters')}
              </button>
              <button type="button" className={buttonClass} disabled={resolveInterfaces.isPending || !specifierInterfaces.trim()} onClick={() => runWithResult('resolveInterfaces', () => resolveInterfaces.mutate({ interfaces: specifierInterfaces || undefined, nodes: specifierNodes || undefined, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.interfaces')}
              </button>
              <button type="button" className={buttonClass} disabled={resolveLocations.isPending || !locations.trim()} onClick={() => runWithResult('resolveLocations', () => resolveLocations.mutate({ locations: locations || undefined, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.locations')}
              </button>
              <button type="button" className={buttonClass} disabled={resolveIps.isPending || !ips.trim()} onClick={() => runWithResult('resolveIps', () => resolveIps.mutate({ ips: ips || undefined, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.ips')}
              </button>
              <button type="button" className={buttonClass} disabled={resolveIpsOfLocation.isPending || !locations.trim()} onClick={() => runWithResult('resolveIpsOfLocation', () => resolveIpsOfLocation.mutate({ locations, grammarVersion: grammarVersion || undefined }))}>
                <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.locationIps')}
              </button>
            </div>
          </section>
        )}

        {activeCategory === 'filters' && (
          <section className="space-y-4" aria-label={t('batfishTools.sections.filterRoutingAnalysis')}>
            <SectionIntro
              icon={<Network className="h-4 w-4 text-blue-600" aria-hidden="true" />}
              title={t('batfishTools.sections.filterRoutingAnalysis')}
              description={t('batfishTools.categoryDescriptions.filters')}
            />
            <SegmentedControl
              label={t('batfishTools.operationLabels.filters')}
              options={filterToolOptions}
              value={activeFilterTool}
              onChange={selectFilterTool}
            />
            <OperationDescription description={t(`batfishTools.operationDescriptions.filters.${activeFilterTool}`)} />

            {activeFilterTool === 'compare' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.referenceSnapshot')}>
                    <select className={textInputClass} value={compareReferenceSnapshot} onChange={(event) => setCompareReferenceSnapshot(event.target.value)}>
                      <option value="">{t('batfishTools.options.selectSnapshot')}</option>
                      {snapshotOptions.map((name) => <option key={name} value={name}>{name}</option>)}
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.currentSnapshotOverride')}>
                    <select className={textInputClass} value={compareSnapshot} onChange={(event) => setCompareSnapshot(event.target.value)}>
                      <option value="">{t('batfishTools.options.activeSnapshot')}</option>
                      {snapshotOptions.map((name) => <option key={name} value={name}>{name}</option>)}
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.filters')}>
                    <input className={textInputClass} value={compareFilterNames} onChange={(event) => setCompareFilterNames(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.nodes')}>
                    <input className={textInputClass} value={compareFilterNodes} onChange={(event) => setCompareFilterNodes(event.target.value)} />
                  </Field>
                </div>
                <div className={checkboxActionRowClass}>
                  <label className={checkboxLabelClass}>
                    <input type="checkbox" checked={ignoreComposites} onChange={(event) => setIgnoreComposites(event.target.checked)} />
                    {t('batfishTools.checkboxes.ignoreComposites')}
                  </label>
                  <button type="button" className={buttonClass} disabled={compareFilters.isPending || !compareReferenceSnapshot} onClick={() => runWithResult('compareFilters', () => compareFilters.mutate({ reference_snapshot: compareReferenceSnapshot, snapshot: compareSnapshot || undefined, filters: compareFilterNames || undefined, nodes: compareFilterNodes || undefined, ignoreComposites }))}>
                    <GitCompare className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.compareFilters')}
                  </button>
                </div>
              </div>
            )}

            {activeFilterTool === 'lpm' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-3">
                  <Field label={t('batfishTools.fields.lpmIp')}>
                    <input className={textInputClass} value={lpmIp} onChange={(event) => setLpmIp(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.lpmNodes')}>
                    <input className={textInputClass} value={lpmNodes} onChange={(event) => setLpmNodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.lpmVrfs')}>
                    <input className={textInputClass} value={lpmVrfs} onChange={(event) => setLpmVrfs(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={lpmRoutes.isPending || !lpmIp.trim()} onClick={() => runWithResult('lpmRoutes', () => lpmRoutes.mutate({ ip: lpmIp, nodes: lpmNodes || undefined, vrfs: lpmVrfs || undefined }))}>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.lpmRoutes')}
                </button>
              </div>
            )}

            {activeFilterTool === 'prefix' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.prefix')}>
                    <input className={textInputClass} value={prefix} onChange={(event) => setPrefix(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.prefixTracerNodes')}>
                    <input className={textInputClass} value={prefixNodes} onChange={(event) => setPrefixNodes(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={prefixTracer.isPending || !prefix.trim()} onClick={() => runWithResult('prefixTracer', () => prefixTracer.mutate({ prefix, nodes: prefixNodes || undefined }))}>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.prefixTracer')}
                </button>
              </div>
            )}

            {activeFilterTool === 'bidirectional' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.bidirectionalHeadersJson')}>
                    <textarea className={textareaClass} rows={4} value={bidirectionalHeaders} onChange={(event) => setBidirectionalHeaders(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.pathConstraintsJson')}>
                    <textarea className={textareaClass} rows={4} value={bidirectionalPathConstraints} onChange={(event) => setBidirectionalPathConstraints(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.returnFlowType')}>
                    <input className={textInputClass} value={returnFlowType} onChange={(event) => setReturnFlowType(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={bidirectionalReachability.isPending} onClick={runBidirectionalReachability}>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.bidirectionalReachability')}
                </button>
              </div>
            )}
          </section>
        )}

        {activeCategory === 'policies' && (
          <section className="space-y-4" aria-label={t('batfishTools.sections.routePolicyWorkbench')}>
            <SectionIntro
              icon={<GitBranch className="h-4 w-4 text-indigo-600" aria-hidden="true" />}
              title={t('batfishTools.sections.routePolicyWorkbench')}
              description={t('batfishTools.categoryDescriptions.policies')}
            />
            <SegmentedControl
              label={t('batfishTools.operationLabels.policies')}
              options={policyToolOptions}
              value={activePolicyTool}
              onChange={selectPolicyTool}
            />
            <OperationDescription description={t(`batfishTools.operationDescriptions.policies.${activePolicyTool}`)} />

            {activePolicyTool === 'search' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-3">
                  <Field label={t('batfishTools.fields.searchAction')}>
                    <select className={textInputClass} value={routePolicyAction} onChange={(event) => setRoutePolicyAction(event.target.value)}>
                      <option value="permit">{t('batfishTools.options.permit')}</option>
                      <option value="deny">{t('batfishTools.options.deny')}</option>
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.searchNodes')}>
                    <input className={textInputClass} value={routePolicyNodes} onChange={(event) => setRoutePolicyNodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.searchPolicies')}>
                    <input className={textInputClass} value={routePolicyPolicies} onChange={(event) => setRoutePolicyPolicies(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.inputConstraintsJson')}>
                    <textarea className={textareaClass} rows={3} value={inputConstraints} onChange={(event) => setInputConstraints(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.outputConstraintsJson')}>
                    <textarea className={textareaClass} rows={3} value={outputConstraints} onChange={(event) => setOutputConstraints(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.pathOption')}>
                    <input className={textInputClass} value={pathOption} onChange={(event) => setPathOption(event.target.value)} />
                  </Field>
                </div>
                <div className={checkboxActionRowClass}>
                  <label className={checkboxLabelClass}>
                    <input type="checkbox" checked={perPath} onChange={(event) => setPerPath(event.target.checked)} />
                    {t('batfishTools.checkboxes.perPath')}
                  </label>
                  <button type="button" className={buttonClass} disabled={searchRoutePolicies.isPending} onClick={runSearchRoutePolicies}>
                    <Search className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.searchRoutePolicies')}
                  </button>
                </div>
              </div>
            )}

            {activePolicyTool === 'test' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.testDirection')}>
                    <select className={textInputClass} value={testDirection} onChange={(event) => setTestDirection(event.target.value)}>
                      <option value="IN">{t('batfishTools.options.in')}</option>
                      <option value="OUT">{t('batfishTools.options.out')}</option>
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.testNodes')}>
                    <input className={textInputClass} value={testNodes} onChange={(event) => setTestNodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.testPolicies')}>
                    <input className={textInputClass} value={testPolicies} onChange={(event) => setTestPolicies(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.inputRoutesJson')}>
                    <textarea className={textareaClass} rows={4} value={testInputRoutes} onChange={(event) => setTestInputRoutes(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={testRoutePolicies.isPending || !testInputRoutes.trim()} onClick={runTestRoutePolicies}>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.testRoutePolicies')}
                </button>
              </div>
            )}

            {activePolicyTool === 'transfer' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.transferNodes')}>
                    <input className={textInputClass} value={transferNodes} onChange={(event) => setTransferNodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.transferPolicies')}>
                    <input className={textInputClass} value={transferPolicies} onChange={(event) => setTransferPolicies(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.seed')}>
                    <input className={textInputClass} value={transferSeed} onChange={(event) => setTransferSeed(event.target.value)} />
                  </Field>
                </div>
                <div className={checkboxActionRowClass}>
                  <label className={checkboxLabelClass}>
                    <input type="checkbox" checked={retainAllPaths} onChange={(event) => setRetainAllPaths(event.target.checked)} />
                    {t('batfishTools.checkboxes.retainAllPaths')}
                  </label>
                  <button type="button" className={buttonClass} disabled={transferBDD.isPending} onClick={runTransferBDDValidation}>
                    <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.transferBddValidation')}
                  </button>
                </div>
              </div>
            )}

            {activePolicyTool === 'compare' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-3">
                  <Field label={t('batfishTools.fields.routeCompareReferenceSnapshot')}>
                    <select className={textInputClass} value={routeCompareReferenceSnapshot} onChange={(event) => setRouteCompareReferenceSnapshot(event.target.value)}>
                      <option value="">{t('batfishTools.options.selectSnapshot')}</option>
                      {snapshotOptions.map((name) => <option key={name} value={name}>{name}</option>)}
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.routeCompareSnapshotOverride')}>
                    <select className={textInputClass} value={routeCompareSnapshot} onChange={(event) => setRouteCompareSnapshot(event.target.value)}>
                      <option value="">{t('batfishTools.options.activeSnapshot')}</option>
                      {snapshotOptions.map((name) => <option key={name} value={name}>{name}</option>)}
                    </select>
                  </Field>
                  <Field label={t('batfishTools.fields.policy')}>
                    <input className={textInputClass} value={comparePolicy} onChange={(event) => setComparePolicy(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.referencePolicy')}>
                    <input className={textInputClass} value={referencePolicy} onChange={(event) => setReferencePolicy(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.compareNodes')}>
                    <input className={textInputClass} value={compareRouteNodes} onChange={(event) => setCompareRouteNodes(event.target.value)} />
                  </Field>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" className={buttonClass} disabled={compareRoutePolicies.isPending || !routeCompareReferenceSnapshot || !comparePolicy.trim() || !referencePolicy.trim()} onClick={() => runWithResult('compareRoutePolicies', () => compareRoutePolicies.mutate({ policy: comparePolicy, referencePolicy, reference_snapshot: routeCompareReferenceSnapshot, snapshot: routeCompareSnapshot || undefined, nodes: compareRouteNodes || undefined }))}>
                    <GitCompare className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.compareRoutePolicies')}
                  </button>
                  <button type="button" className={buttonClass} disabled={comparePeerGroups.isPending || !routeCompareReferenceSnapshot} onClick={() => runWithResult('comparePeerGroups', () => comparePeerGroups.mutate({ reference_snapshot: routeCompareReferenceSnapshot, snapshot: routeCompareSnapshot || undefined }))}>
                    <GitCompare className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.comparePeerGroups')}
                  </button>
                </div>
              </div>
            )}
          </section>
        )}

        {activeCategory === 'edge' && (
          <section className="space-y-4" aria-label={t('batfishTools.sections.loadBalancerLayer1')}>
            <SectionIntro
              icon={<Server className="h-4 w-4 text-emerald-600" aria-hidden="true" />}
              title={t('batfishTools.sections.loadBalancerLayer1')}
              description={t('batfishTools.categoryDescriptions.edge')}
            />
            <SegmentedControl
              label={t('batfishTools.operationLabels.edge')}
              options={edgeToolOptions}
              value={activeEdgeTool}
              onChange={selectEdgeTool}
            />
            <OperationDescription description={t(`batfishTools.operationDescriptions.edge.${activeEdgeTool}`)} />

            {activeEdgeTool === 'a10' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.a10Nodes')}>
                    <input className={textInputClass} value={a10Nodes} onChange={(event) => setA10Nodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.a10VirtualServerIps')}>
                    <input className={textInputClass} value={a10VirtualServerIps} onChange={(event) => setA10VirtualServerIps(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={a10VirtualServers.isPending} onClick={() => runWithResult('a10VirtualServers', () => a10VirtualServers.mutate({ nodes: a10Nodes || undefined, virtualServerIps: a10VirtualServerIps || undefined }))}>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.a10VirtualServers')}
                </button>
              </div>
            )}

            {activeEdgeTool === 'layer1' && (
              <div className="space-y-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label={t('batfishTools.fields.layer1Nodes')}>
                    <input className={textInputClass} value={layer1Nodes} onChange={(event) => setLayer1Nodes(event.target.value)} />
                  </Field>
                  <Field label={t('batfishTools.fields.layer1RemoteNodes')}>
                    <input className={textInputClass} value={layer1RemoteNodes} onChange={(event) => setLayer1RemoteNodes(event.target.value)} />
                  </Field>
                </div>
                <button type="button" className={buttonClass} disabled={userLayer1Edges.isPending} onClick={() => runWithResult('userLayer1Edges', () => userLayer1Edges.mutate({ nodes: layer1Nodes || undefined, remoteNodes: layer1RemoteNodes || undefined }))}>
                  <Layers className="h-3.5 w-3.5" aria-hidden="true" /> {t('batfishTools.buttons.userProvidedLayer1Edges')}
                </button>
              </div>
            )}
          </section>
        )}

        {activeResultView && (
          <ResultBlock title={activeResultView.title} mutation={activeResultView.mutation} labels={resultLabels} />
        )}
      </div>
    </div>
  )
}

export default BatfishFeatureTools
