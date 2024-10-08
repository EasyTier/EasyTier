import { z } from 'zod'
import type { Config } from '~/components/ui/auto-form/interface'
import type { ZodObjectOrWrapped } from '~/components/ui/auto-form/utils'

export const createConfigWithNameSchema = computed<ZodObjectOrWrapped>(() => z.object({
  instance_name: z.string().describe('Instance username'),
}))

export const createConfigWithNameConfig = computed<Config<z.infer<any>>>(() => {
  const { t } = useI18n()

  return {
    instance_name: {
      label: t('form.instance.instance_name'),
    },
  }
})

export const configBaseSchema = computed<ZodObjectOrWrapped>(() => {
  return z.object({
    network_name: z.string().describe('Your username'),
    network_secret: z.string().optional(),
    hostname: z.string().describe('The hostname to use').optional(),
    ipv4: z.string().describe('The IPv4 address to use').ip('v4').optional(),
    dhcp: z.boolean().describe('Whether to enable DHCP').default(false).optional(),
    instance_name: z.string().describe('The name of the instance').optional(),
    listeners: z.array(z.string()).describe('The listeners to use').optional(),
    rpc_portal: z.string().describe('The RPC portal to use').default('127.0.0.1:15888').optional(),
    uri: z.array(z.string()).describe('The URI of the peer').optional(),
    cidr: z.array(z.string()).describe('The CIDR of the proxy network').optional(),
    exit_node: z.array(z.string()).describe('The exit node to use').optional(),
    instance_id: z.string().describe('The ID of the instance').uuid().optional(),
  })
})

export const configBaseConfig = computed<Config<z.infer<any>>>(() => {
  const { t } = useI18n()
  return {
    instance_name: {
      label: t('form.instance.instance_name'),
    },
    hostname: {
      label: t('form.instance.hostname'),
    },
    instance_id: {
      label: t('form.instance.instance_id'),
    },
    ipv4: {
      label: t('form.instance.ipv4'),
    },
    dhcp: {
      label: t('form.instance.dhcp'),
    },
    listeners: {
      label: t('form.instance.listeners'),
    },
    exit_node: {
      label: t('form.instance.exit_node'),
    },
    rpc_portal: {
      label: t('form.instance.rpc_portal'),
    },
    network_name: {
      label: t('form.instance.network_name'),
    },
    network_secret: {
      label: t('form.instance.network_secret'),
    },
  }
})

export const configCommonSchema = computed<ZodObjectOrWrapped>(() => z.object({
  flags: z.object({
    default_protocol: z.string().describe('The default protocol to use').default('tcp').optional(),
    dev_name: z.string().describe('The name of the device').optional(),
    enable_encryption: z.boolean().describe('Whether to enable encryption').default(true).optional(),
    enable_ipv6: z.boolean().describe('Whether to enable IPv6').default(true).optional(),
    mtu: z.number().describe('The MTU to use').default(1380).optional(),
    latency_first: z.boolean().describe('The latency to use').default(false).optional(),
    enable_exit_node: z.boolean().describe('Whether to enable exit nodes').default(false).optional(),
    no_tun: z.boolean().describe('Whether to disable the TUN interface').default(false).optional(),
    use_smoltcp: z.boolean().describe('Whether to use smoltcp').default(false).optional(),
    foreign_network_whitelist: z.string().describe('A comma-separated list of networks to allow').default('*').optional(),
  }).optional(),
}))

export const DEFAULT_DEPENDENCIES = {}

export const appAutostartSchema = computed<ZodObjectOrWrapped>(() => {
  return z.object({
    autostart: z.boolean().default(false),
    list: z.array(z.string()).optional(),
  })
})
