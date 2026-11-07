import { api } from './api'
import { fromB64 } from './bytes'

export function pushSupported(): boolean {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window
}

export async function currentSubscription(): Promise<PushSubscription | null> {
  if (!pushSupported()) return null
  const reg = await navigator.serviceWorker.ready
  return reg.pushManager.getSubscription()
}

export async function enablePush(vapidPublicKey: string): Promise<void> {
  if (!pushSupported()) throw new Error('This device does not support push notifications')
  const permission = await Notification.requestPermission()
  if (permission !== 'granted') throw new Error('Notifications were not allowed. You can enable them in system settings.')
  const reg = await navigator.serviceWorker.ready
  let sub = await reg.pushManager.getSubscription()
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64(vapidPublicKey) })
  await api('/api/app/push/subscribe', { method: 'POST', body: sub.toJSON() })
}
