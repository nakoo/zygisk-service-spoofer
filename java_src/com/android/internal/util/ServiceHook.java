package com.android.internal.util;

import android.os.IBinder;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class ServiceHook implements InvocationHandler {
    private final Object target;

    public ServiceHook(Object target) {
        this.target = target;
    }

    public static boolean shouldHide(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.equals("profile")) return true;
        if (lower.contains("lineage")) return true;
        if (lower.contains("crdroid")) return true;
        if (lower.contains("aospa")) return true;
        if (lower.contains("pixelexperience")) return true;
        if (lower.contains("omnirom")) return true;
        if (lower.contains("protonaosp")) return true;
        return false;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();

        // If any parameter is a service name that should be hidden, return null immediately
        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof String && shouldHide((String) arg)) {
                    return null;
                }
            }
        }

        if ("listServices".equals(name)) {
            Object res = method.invoke(target, args);
            if (res instanceof String[]) {
                String[] list = (String[]) res;
                List<String> filtered = new ArrayList<>(list.length);
                for (String s : list) {
                    if (!shouldHide(s)) {
                        filtered.add(s);
                    }
                }
                return filtered.toArray(new String[0]);
            }
        }
        return method.invoke(target, args);
    }

    public static class FilteredCache<K, V> extends HashMap<K, V> {
        public FilteredCache() {
            super();
        }

        private boolean shouldHideKey(Object key) {
            return key instanceof String && shouldHide((String) key);
        }

        @Override
        public V get(Object key) {
            if (shouldHideKey(key)) return null;
            return super.get(key);
        }

        @Override
        public boolean containsKey(Object key) {
            if (shouldHideKey(key)) return false;
            return super.containsKey(key);
        }

        @Override
        public V put(K key, V value) {
            if (shouldHideKey(key)) return null;
            return super.put(key, value);
        }

        @Override
        public void putAll(Map<? extends K, ? extends V> m) {
            if (m == null) return;
            for (Map.Entry<? extends K, ? extends V> entry : m.entrySet()) {
                put(entry.getKey(), entry.getValue());
            }
        }
    }

    public static void install() {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getSmMethod = smClass.getDeclaredMethod("getIServiceManager");
            getSmMethod.setAccessible(true);
            Object orig = getSmMethod.invoke(null);
            if (orig != null) {
                Class<?> ismClass = Class.forName("android.os.IServiceManager");
                Object proxy = Proxy.newProxyInstance(
                    ismClass.getClassLoader(),
                    new Class<?>[] { ismClass },
                    new ServiceHook(orig)
                );

                Field ssmField = smClass.getDeclaredField("sServiceManager");
                ssmField.setAccessible(true);
                ssmField.set(null, proxy);
            }

            Field sCacheField = smClass.getDeclaredField("sCache");
            sCacheField.setAccessible(true);
            Object cacheObj = sCacheField.get(null);

            // 1. Purge existing entries in-place
            if (cacheObj instanceof Map) {
                Map<?, ?> oldMap = (Map<?, ?>) cacheObj;
                synchronized (oldMap) {
                    Iterator<?> it = oldMap.keySet().iterator();
                    while (it.hasNext()) {
                        Object key = it.next();
                        if (key instanceof String && shouldHide((String) key)) {
                            it.remove();
                        }
                    }
                }
            }

            // 2. Overwrite the final static field using Unsafe so any future putAll/initServiceCache drops "profile"
            FilteredCache<String, IBinder> newCache = new FilteredCache<>();
            if (cacheObj instanceof Map) {
                Map<?, ?> oldMap = (Map<?, ?>) cacheObj;
                for (Map.Entry<?, ?> entry : oldMap.entrySet()) {
                    if (entry.getKey() instanceof String && entry.getValue() instanceof IBinder) {
                        newCache.put((String) entry.getKey(), (IBinder) entry.getValue());
                    }
                }
            }

            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                Field theUnsafeField = unsafeClass.getDeclaredField("theUnsafe");
                theUnsafeField.setAccessible(true);
                Object unsafe = theUnsafeField.get(null);

                Method staticFieldOffsetMethod = unsafeClass.getMethod("staticFieldOffset", Field.class);
                Method staticFieldBaseMethod = unsafeClass.getMethod("staticFieldBase", Field.class);
                Method putObjectMethod = unsafeClass.getMethod("putObject", Object.class, long.class, Object.class);

                long offset = ((Number) staticFieldOffsetMethod.invoke(unsafe, sCacheField)).longValue();
                Object base = staticFieldBaseMethod.invoke(unsafe, sCacheField);
                putObjectMethod.invoke(unsafe, base, offset, newCache);
            } catch (Throwable fallback) {
                sCacheField.set(null, newCache);
            }
        } catch (Throwable ignored) {
        }

        // Nullify AssetManager.LINEAGE_APK_PATH to clear reflectionScan
        try {
            Class<?> amClass = Class.forName("android.content.res.AssetManager");
            Field field = amClass.getDeclaredField("LINEAGE_APK_PATH");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Throwable ignored) {
        }
    }
}
