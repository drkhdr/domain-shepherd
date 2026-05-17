import packageJson from '../../package.json'

export const APP_NAME = 'Domain Shepherd'
export const APP_VERSION = typeof packageJson.version === 'string' ? packageJson.version : '0.1.0'
export const APP_GIT_SHA = (process.env.NEXT_PUBLIC_GIT_SHA || '').trim() || 'unknown'
export const APP_VERSION_WITH_GIT = APP_GIT_SHA !== 'unknown' ? `${APP_VERSION}+g${APP_GIT_SHA}` : APP_VERSION

export const LOCAL_LIST_STORAGE_KEY = 'domainshepherd:list:v1'
export const LOCAL_SETTINGS_STORAGE_KEY = 'domainshepherd:settings:v1'

export const SETTINGS_OPEN_EVENT = 'domainshepherd:open-settings'
