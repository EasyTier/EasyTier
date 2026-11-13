<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { v4 as uuidv4 } from 'uuid';
import { Button, Drawer, InputNumber, InputText, InputSwitch, Message, MultiSelect, Select, SelectButton, useToast } from 'primevue';
import { useI18n } from 'vue-i18n';
import ApiClient, { type AclPolicy, type AclPolicyRule, type AclProtocolTarget, type AclSelector, type CentralNetworkMember } from '../modules/api';

const props = defineProps<{
    api: ApiClient;
    networkId: string;
    members: CentralNetworkMember[] | undefined;
}>();

const { t } = useI18n();
const toast = useToast();

// ---- policy state -------------------------------------------------------------

const policy = ref<AclPolicy>({ default_action: 'allow', rules: [] });
const loading = ref(false);
const saving = ref(false);
const dirty = ref(false);
const loadError = ref('');

const memberName = (member_id: string) => {
    const member = props.members?.find(m => m.member_id === member_id);
    return member ? (member.hostname_override || member.alias || member.hostname || member.device_id.slice(0, 8)) : member_id.slice(0, 8);
};

const loadPolicy = async () => {
    loading.value = true;
    loadError.value = '';
    try {
        const info = await props.api.get_network_acl_policy(props.networkId);
        policy.value = info.policy;
        dirty.value = false;
    } catch (e) {
        console.error(e);
        loadError.value = t('web.console.load_failed');
    } finally {
        loading.value = false;
    }
};

watch(() => props.networkId, () => { policy.value = { default_action: 'allow', rules: [] }; loadPolicy(); }, { immediate: true });

const enabledCount = computed(() => policy.value.rules.filter(r => r.enabled).length);

const save = async () => {
    saving.value = true;
    try {
        const info = await props.api.update_network_acl_policy(props.networkId, policy.value);
        policy.value = info.policy;
        dirty.value = false;
        toast.add({ severity: 'success', summary: t('web.acl.saved'), life: 2000 });
    } catch (e: any) {
        console.error(e);
        toast.add({ severity: 'error', summary: e?.response?.data?.message ?? t('web.acl.save_failed'), life: 5000 });
    } finally {
        saving.value = false;
    }
};

const markDirty = () => { dirty.value = true; };

// ---- drag reorder ---------------------------------------------------------------

const dragIndex = ref<number | null>(null);
const dragOverIndex = ref<number | null>(null);

const onDragStart = (index: number) => { dragIndex.value = index; };
const onDragOver = (index: number, event: DragEvent) => {
    event.preventDefault();
    dragOverIndex.value = index;
};
const onDrop = (index: number) => {
    const from = dragIndex.value;
    if (from === null || from === index) return;
    const rules = policy.value.rules;
    const [moved] = rules.splice(from, 1);
    rules.splice(index, 0, moved);
    dragIndex.value = null;
    dragOverIndex.value = null;
    markDirty();
};

// ---- rule editor ----------------------------------------------------------------

type PortEntry = { kind: 'single' | 'range'; start: number | null; end: number | null };

const editorVisible = ref(false);
const editingIndex = ref<number | null>(null);
const editor = ref(blankEditor());

function blankEditor() {
    return {
        name: '',
        action: 'allow' as 'allow' | 'deny',
        enabled: true,
        sourceValues: [] as string[],
        targetValues: [] as string[],
        tcp: { enabled: false, entries: [] as PortEntry[], stateful: true },
        udp: { enabled: false, entries: [] as PortEntry[] },
        icmp: { enabled: false },
        otherProtocols: [] as AclProtocolTarget[],
    };
}

const sourceOptions = computed(() => [
    { label: t('web.acl.all_members'), value: 'all' },
    ...(props.members ?? []).map(m => ({
        label: `${memberName(m.member_id)}${m.virtual_ipv4 ? ` (${m.virtual_ipv4})` : ''}`,
        value: `member:${m.member_id}`,
    })),
    ...[...new Set(policy.value.rules.flatMap(rule => rule.sources
        .filter(source => source.type === 'group')
        .map(source => source.name)))].map(name => ({ label: name, value: `group:${name}` })),
]);

const targetOptions = computed(() => {
    const base = [
        { label: t('web.acl.all_members'), value: 'all' },
        ...(props.members ?? []).map(m => ({
            label: `${memberName(m.member_id)}${m.virtual_ipv4 ? ` (${m.virtual_ipv4})` : ''}`,
            value: `member:${m.member_id}`,
        })),
    ];
    for (const m of props.members ?? []) {
        for (const cidr of m.proxy_cidrs ?? []) {
            base.push({ label: `${t('web.acl.subnet')} · ${memberName(m.member_id)} · ${cidr}`, value: `subnet:${m.member_id}:${cidr}` });
        }
    }
    return base;
});

const openCreateRule = () => {
    editingIndex.value = null;
    editor.value = blankEditor();
    editorVisible.value = true;
};

const openEditRule = (index: number) => {
    const rule = policy.value.rules[index];
    editingIndex.value = index;
    editor.value = {
        name: rule.name,
        action: rule.action,
        enabled: rule.enabled,
        sourceValues: rule.sources.flatMap(selectorValue),
        targetValues: rule.destinations.flatMap(selectorValue),
        tcp: {
            enabled: rule.protocols.some(p => p.protocol === 'tcp'),
            entries: portEntries(rule.protocols.find(p => p.protocol === 'tcp')),
            stateful: rule.protocols.find(p => p.protocol === 'tcp')?.stateful ?? true,
        },
        udp: { enabled: rule.protocols.some(p => p.protocol === 'udp'), entries: portEntries(rule.protocols.find(p => p.protocol === 'udp')) },
        icmp: { enabled: rule.protocols.some(p => p.protocol === 'icmp') },
        otherProtocols: rule.protocols.filter(p => p.protocol === 'icmpv6' || p.protocol === 'any'),
    };
    editorVisible.value = true;
};

const selectorValue = (selector: AclSelector): string[] => {
    switch (selector.type) {
        case 'all': return ['all'];
        case 'member': return [`member:${selector.member_id}`];
        case 'subnet': return selector.cidrs.map(cidr => `subnet:${selector.member_id}:${cidr}`);
        case 'group': return [`group:${selector.name}`];
    }
};

const portEntries = (target: AclProtocolTarget | undefined): PortEntry[] =>
    (target?.ports ?? []).map(port => {
        const [start, end] = port.split('-');
        return { kind: end === undefined ? 'single' : 'range', start: Number(start), end: end === undefined ? null : Number(end) };
    });

const swapSourceTarget = () => {
    const sources = editor.value.sourceValues;
    const targets = editor.value.targetValues.filter(v => !v.startsWith('subnet:'));
    if (editor.value.targetValues.some(v => v.startsWith('subnet:'))
        || sources.some(v => v.startsWith('group:'))) return;
    editor.value.sourceValues = targets;
    editor.value.targetValues = sources;
};

const addPortEntry = (proto: 'tcp' | 'udp', kind: 'single' | 'range') => {
    editor.value[proto].entries.push({ kind, start: null, end: null });
};
const addAllPorts = (proto: 'tcp' | 'udp') => {
    editor.value[proto].entries = [{ kind: 'range', start: 1, end: 65535 }];
};
const quickPorts: Record<'tcp' | 'udp', { label: string; value: [number, number] }[]> = {
    tcp: [
        { label: 'SSH 22', value: [22, 22] },
        { label: 'HTTP 80', value: [80, 80] },
        { label: 'HTTPS 443', value: [443, 443] },
        { label: 'RDP 3389', value: [3389, 3389] },
        { label: 'MySQL 3306', value: [3306, 3306] },
    ],
    udp: [{ label: 'DNS 53', value: [53, 53] }],
};
const appendQuickPort = (proto: 'tcp' | 'udp', value: [number, number]) => {
    const exists = editor.value[proto].entries.some(e => e.start === value[0] && e.end === value[1]);
    if (!exists) editor.value[proto].entries.push({ kind: value[0] === value[1] ? 'single' : 'range', start: value[0], end: value[1] });
};

const editorError = ref('');

const saveRule = () => {
    const e = editor.value;
    if (!e.name.trim()) { editorError.value = t('web.acl.error_name'); return; }
    if (e.sourceValues.length === 0) { editorError.value = t('web.acl.error_source'); return; }
    if (e.targetValues.length === 0) { editorError.value = t('web.acl.error_target'); return; }
    const protocols: AclProtocolTarget[] = [];
    if (e.tcp.enabled) {
        const ports = e.tcp.entries.map(entryToString).filter((p): p is string => !!p);
        if (ports.length === 0) { editorError.value = t('web.acl.error_ports', { protocol: 'TCP' }); return; }
        protocols.push({ protocol: 'tcp', ports, stateful: e.action === 'allow' && e.tcp.stateful });
    }
    if (e.udp.enabled) {
        const ports = e.udp.entries.map(entryToString).filter((p): p is string => !!p);
        if (ports.length === 0) { editorError.value = t('web.acl.error_ports', { protocol: 'UDP' }); return; }
        protocols.push({ protocol: 'udp', ports, stateful: false });
    }
    if (e.icmp.enabled) protocols.push({ protocol: 'icmp', ports: [], stateful: false });
    protocols.push(...e.otherProtocols);
    if (protocols.length === 0) { editorError.value = t('web.acl.error_protocol'); return; }

    const sources = e.sourceValues.map(parseSelector);
    const destinations = e.targetValues.map(parseSelector);

    const rule: AclPolicyRule = {
        id: editingIndex.value === null ? uuidv4() : policy.value.rules[editingIndex.value].id,
        name: e.name.trim(),
        enabled: e.enabled,
        action: e.action,
        sources,
        destinations,
        protocols,
    };
    if (editingIndex.value === null) policy.value.rules.push(rule);
    else policy.value.rules[editingIndex.value] = rule;
    editorVisible.value = false;
    markDirty();
};

const parseSelector = (value: string): AclSelector => {
    if (value === 'all') return { type: 'all' };
    if (value.startsWith('member:')) return { type: 'member', member_id: value.slice('member:'.length) };
    if (value.startsWith('group:')) return { type: 'group', name: value.slice('group:'.length) };
    if (value.startsWith('subnet:')) {
        const rest = value.slice('subnet:'.length);
        const sep = rest.indexOf(':');
        return { type: 'subnet', member_id: rest.slice(0, sep), cidrs: [rest.slice(sep + 1)] };
    }
    throw new Error(`Unknown ACL selector: ${value}`);
};

const entryToString = (entry: PortEntry): string | null => {
    if (entry.start === null) return null;
    if (entry.kind === 'single') return String(entry.start);
    if (entry.end === null || entry.end < entry.start) return null;
    return `${entry.start}-${entry.end}`;
};

const removeRule = (index: number) => {
    policy.value.rules.splice(index, 1);
    markDirty();
};

// ---- display helpers ------------------------------------------------------------

const selectorLabel = (selector: AclSelector): string => {
    switch (selector.type) {
        case 'all': return t('web.acl.all_members');
        case 'member': return memberName(selector.member_id);
        case 'subnet': {
            const cidr = selector.cidrs?.[0] ?? '';
            return `${t('web.acl.subnet')} ${memberName(selector.member_id)} ${cidr}`.trim();
        }
        case 'group': return selector.name;
    }
};

const protocolLabel = (target: AclProtocolTarget): string => {
    const proto = target.protocol.toUpperCase();
    if (target.protocol === 'icmp') return 'ICMP';
    const ports = target.ports;
    if (ports.length === 0) return proto;
    if (ports.length === 1 && ports[0] === '1-65535') return `${proto} ${t('web.acl.all_ports')}`;
    return `${proto} ${ports.join(', ')}`;
};

const defaultActionOptions = [
    { label: t('web.acl.default_allow'), value: 'allow' },
    { label: t('web.acl.default_deny'), value: 'deny' },
];
</script>

<template>
    <div class="flex flex-col gap-3">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-3 flex-wrap">
                <span class="text-sm font-medium">{{ t('web.acl.default_action') }}</span>
                <SelectButton v-model="policy.default_action" :options="defaultActionOptions"
                    optionLabel="label" optionValue="value" size="small" @update:model-value="markDirty" />
                <span class="text-xs muted">{{ policy.default_action === 'deny'
                    ? t('web.acl.default_deny_hint') : t('web.acl.default_allow_hint') }}</span>
            </div>
            <div class="flex items-center gap-2">
                <span class="table-count">{{ t('web.acl.rule_summary', { total: policy.rules.length, enabled: enabledCount }) }}</span>
                <span v-if="dirty" class="text-xs" style="color: var(--p-orange-400)">{{ t('web.acl.unsaved') }}</span>
                <Button icon="pi pi-plus" :label="t('web.acl.add_rule')" size="small" @click="openCreateRule" />
                <Button icon="pi pi-check" :label="t('web.acl.save')" size="small" severity="primary"
                    :loading="saving" :disabled="!dirty" @click="save" />
            </div>
        </div>

        <Message v-if="loadError" severity="error">{{ loadError }}</Message>

        <div class="console-panel">
            <div v-if="policy.rules.length === 0" class="console-empty-state">
                <i class="pi pi-shield" aria-hidden="true"></i>
                <h2>{{ t('web.acl.empty_title') }}</h2>
                <p>{{ policy.default_action === 'deny' ? t('web.acl.empty_deny') : t('web.acl.empty_allow') }}</p>
            </div>
            <div v-else class="acl-rule-list">
                <div v-for="(rule, index) in policy.rules" :key="rule.id" class="acl-rule-row"
                    :class="{ 'acl-rule-row--dragging': dragIndex === index, 'acl-rule-row--over': dragOverIndex === index && dragIndex !== index }"
                    draggable="true" @dragstart="onDragStart(index)" @dragover="onDragOver(index, $event)"
                    @drop="onDrop(index)" @dragend="dragIndex = null; dragOverIndex = null">
                    <div class="flex items-center gap-2 shrink-0" @click.stop>
                        <span class="pi pi-bars acl-rule-drag" :title="t('web.acl.drag_hint')"></span>
                        <span class="acl-rule-index" :class="rule.action">{{ index + 1 }}</span>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-medium truncate">{{ rule.name }}</span>
                            <span class="acl-badge" :class="rule.action">{{ rule.action === 'allow' ? t('web.acl.allow') : t('web.acl.deny') }}</span>
                            <span v-if="!rule.enabled" class="acl-badge muted">{{ t('web.acl.disabled') }}</span>
                            <span class="flex-1"></span>
                            <Button icon="pi pi-pencil" text rounded severity="secondary" size="small"
                                :aria-label="t('web.common.edit')" @click.stop="openEditRule(index)" />
                            <Button icon="pi pi-trash" text rounded severity="danger" size="small"
                                :aria-label="t('web.common.delete')" @click.stop="removeRule(index)" />
                        </div>
                        <div class="flex items-center gap-2 flex-wrap text-xs mt-1">
                            <span class="muted">{{ t('web.acl.source') }}</span>
                            <span v-for="source in rule.sources" :key="`s-${rule.id}-${selectorLabel(source)}`"
                                class="acl-chip">{{ selectorLabel(source) }}</span>
                            <i class="pi pi-arrow-right muted" aria-hidden="true"></i>
                            <span class="muted">{{ t('web.acl.target') }}</span>
                            <span v-for="target in rule.destinations" :key="`d-${rule.id}-${selectorLabel(target)}`"
                                class="acl-chip">{{ selectorLabel(target) }}</span>
                            <span class="muted">·</span>
                            <span v-for="target in rule.protocols" :key="`p-${rule.id}-${target.protocol}`"
                                class="acl-chip proto">{{ protocolLabel(target) }}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <Drawer v-model:visible="editorVisible" position="right" :style="{ width: 'min(46rem, 96vw)' }"
            :header="editingIndex === null ? t('web.acl.add_rule') : t('web.acl.edit_rule')">
            <div class="flex flex-col gap-4">
                <div class="flex items-center gap-3 flex-wrap">
                    <div class="flex-1 min-w-[14rem]">
                        <label class="text-sm font-medium" for="acl-rule-name">{{ t('web.acl.rule_name') }}</label>
                        <InputText id="acl-rule-name" v-model="editor.name" class="w-full mt-1"
                            :placeholder="t('web.acl.name_placeholder')" :maxlength="64" />
                    </div>
                    <div>
                        <label class="text-sm font-medium" for="acl-rule-action">{{ t('web.acl.action') }}</label>
                        <Select inputId="acl-rule-action" v-model="editor.action" class="w-36 mt-1"
                            :options="[{ label: t('web.acl.allow'), value: 'allow' }, { label: t('web.acl.deny'), value: 'deny' }]"
                            optionLabel="label" optionValue="value" />
                    </div>
                    <div class="flex items-center gap-2 mt-4">
                        <InputSwitch inputId="acl-rule-enabled" v-model="editor.enabled" />
                        <label for="acl-rule-enabled" class="text-sm">{{ t('web.acl.enabled') }}</label>
                    </div>
                </div>

                <div class="flex flex-col gap-1">
                    <div class="flex items-center justify-between">
                        <label class="text-sm font-medium">{{ t('web.acl.source') }}</label>
                        <Button :label="t('web.acl.swap')" text size="small"
                        :disabled="editor.targetValues.some(v => v.startsWith('subnet:')) || editor.sourceValues.some(v => v.startsWith('group:'))" @click="swapSourceTarget" />
                    </div>
                    <MultiSelect v-model="editor.sourceValues" :options="sourceOptions" optionLabel="label"
                        optionValue="value" filter :maxSelectedLabels="6" :placeholder="t('web.acl.source_placeholder')"
                        class="w-full" />
                </div>

                <div class="flex flex-col gap-1">
                    <label class="text-sm font-medium">{{ t('web.acl.target') }}</label>
                    <MultiSelect v-model="editor.targetValues" :options="targetOptions" optionLabel="label"
                        optionValue="value" filter :maxSelectedLabels="6" :placeholder="t('web.acl.target_placeholder')"
                        class="w-full" />
                    <div class="text-xs muted">{{ t('web.acl.target_hint') }}</div>
                </div>

                <div class="flex flex-col gap-2">
                    <label class="text-sm font-medium">{{ t('web.acl.protocols') }}</label>
                    <div class="flex items-center gap-4">
                        <label class="flex items-center gap-2">
                            <input type="checkbox" v-model="editor.tcp.enabled" /> TCP
                        </label>
                        <label class="flex items-center gap-2">
                            <input type="checkbox" v-model="editor.udp.enabled" /> UDP
                        </label>
                        <label class="flex items-center gap-2">
                            <input type="checkbox" v-model="editor.icmp.enabled" /> ICMP
                        </label>
                    </div>

                    <div v-for="proto of (['tcp', 'udp'] as const)" v-show="editor[proto].enabled" :key="proto"
                        class="acl-port-block">
                        <div class="flex items-center justify-between">
                            <span class="font-medium text-sm">{{ proto.toUpperCase() }}</span>
                            <div v-if="proto === 'tcp' && editor.action === 'allow'" class="flex items-center gap-2">
                                <span class="text-xs muted">{{ t('web.acl.stateful') }}</span>
                                <InputSwitch v-model="editor.tcp.stateful" v-tooltip.top="t('web.acl.stateful_hint')" />
                            </div>
                        </div>
                        <div v-for="(entry, entryIndex) in editor[proto].entries" :key="entryIndex"
                            class="flex items-center gap-2 mt-2">
                            <Select v-model="entry.kind" :options="[
                                { label: t('web.acl.port_single'), value: 'single' },
                                { label: t('web.acl.port_range'), value: 'range' }]"
                                optionLabel="label" optionValue="value" size="small" class="w-28" />
                            <InputNumber v-model="entry.start" :min="1" :max="65535" :useGrouping="false"
                                class="w-24" :placeholder="t('web.acl.port_start')" />
                            <template v-if="entry.kind === 'range'">
                                <span class="text-sm muted">{{ t('web.acl.port_to') }}</span>
                                <InputNumber v-model="entry.end" :min="1" :max="65535" :useGrouping="false"
                                    class="w-24" :placeholder="t('web.acl.port_end')" />
                            </template>
                            <Button icon="pi pi-times" text rounded severity="danger" size="small"
                                :aria-label="t('web.common.delete')"
                                @click="editor[proto].entries.splice(entryIndex, 1)" />
                        </div>
                        <div class="flex items-center gap-2 mt-2 flex-wrap">
                            <Button :label="t('web.acl.add_port')" size="small" severity="secondary"
                                @click="addPortEntry(proto, 'single')" />
                            <Button :label="t('web.acl.add_range')" size="small" severity="secondary"
                                @click="addPortEntry(proto, 'range')" />
                            <Button :label="t('web.acl.all_ports')" size="small" severity="secondary"
                                @click="addAllPorts(proto)" />
                            <span class="muted text-xs">{{ t('web.acl.quick_add') }}:</span>
                            <Button v-for="quick in quickPorts[proto]" :key="quick.label" :label="quick.label"
                                size="small" text severity="info" @click="appendQuickPort(proto, quick.value)" />
                        </div>
                    </div>
                    <div v-if="editor.icmp.enabled" class="text-xs muted">{{ t('web.acl.icmp_note') }}</div>
                </div>

                <Message v-if="editorError" severity="error" :closable="false">{{ editorError }}</Message>
            </div>
            <template #footer>
                <Button :label="t('web.common.cancel')" severity="secondary" @click="editorVisible = false" />
                <Button :label="t('web.acl.save_rule')" severity="primary" @click="saveRule" />
            </template>
        </Drawer>
    </div>
</template>

<style scoped>
.acl-rule-list { display: flex; flex-direction: column; }
.acl-rule-row { display: flex; gap: 12px; align-items: flex-start; padding: 12px 16px; border-bottom: 1px solid var(--console-border); cursor: pointer; }
.acl-rule-row:last-child { border-bottom: 0; }
.acl-rule-row:hover { background: var(--p-content-hover-background); }
.acl-rule-row--dragging { opacity: 0.4; }
.acl-rule-row--over { box-shadow: inset 0 2px 0 var(--p-primary-color); }
.acl-rule-drag { cursor: grab; color: var(--console-muted); font-size: 13px; padding-top: 6px; }
.acl-rule-index { display: inline-flex; width: 26px; height: 26px; border-radius: 6px; align-items: center; justify-content: center; font-size: 13px; font-weight: 600; }
.acl-rule-index.allow { background: var(--p-green-100); color: var(--p-green-700); }
.acl-rule-index.deny { background: var(--p-red-100); color: var(--p-red-700); }
html.app-dark .acl-rule-index.allow { background: color-mix(in srgb, var(--p-green-500) 22%, transparent); color: var(--p-green-300); }
html.app-dark .acl-rule-index.deny { background: color-mix(in srgb, var(--p-red-500) 22%, transparent); color: var(--p-red-300); }
.acl-badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
.acl-badge.allow { background: var(--p-green-100); color: var(--p-green-700); }
.acl-badge.deny { background: var(--p-red-100); color: var(--p-red-700); }
html.app-dark .acl-badge.allow { background: color-mix(in srgb, var(--p-green-500) 22%, transparent); color: var(--p-green-300); }
html.app-dark .acl-badge.deny { background: color-mix(in srgb, var(--p-red-500) 22%, transparent); color: var(--p-red-300); }
.acl-badge.muted { background: var(--p-content-border); color: var(--p-text-muted-color); }
.acl-badge.warn { background: var(--p-orange-100); color: var(--p-orange-700); }
html.app-dark .acl-badge.warn { background: color-mix(in srgb, var(--p-orange-500) 22%, transparent); color: var(--p-orange-300); }
.acl-chip { background: var(--p-content-border); border-radius: 999px; padding: 1px 8px; color: var(--p-text-color); white-space: nowrap; }
.acl-chip.proto { background: color-mix(in srgb, var(--p-primary-color) 14%, transparent); color: var(--p-primary-color); }
.acl-port-block { border: 1px solid var(--console-border); border-radius: 8px; padding: 12px 16px; }
</style>
