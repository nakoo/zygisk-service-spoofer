package com.android.internal.util;

import android.os.IBinder;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class ServiceHook implements InvocationHandler {
    private final Object target;

    public ServiceHook(Object target) {
        this.target = target;
    }

    private static boolean shouldHide(String name) {
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
        if ("getService".equals(name) || "checkService".equals(name)) {
            if (args != null && args.length > 0 && args[0] instanceof String) {
                if (shouldHide((String) args[0])) {
                    return null;
                }
            }
        } else if ("listServices".equals(name)) {
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

    public static void install() {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getSmMethod = smClass.getDeclaredMethod("getIServiceManager");
            getSmMethod.setAccessible(true);
            Object orig = getSmMethod.invoke(null);
            if (orig == null) return;

            Class<?> ismClass = Class.forName("android.os.IServiceManager");
            Object proxy = Proxy.newProxyInstance(
                ismClass.getClassLoader(),
                new Class<?>[] { ismClass },
                new ServiceHook(orig)
            );

            Field ssmField = smClass.getDeclaredField("sServiceManager");
            ssmField.setAccessible(true);
            ssmField.set(null, proxy);

            Field sCacheField = smClass.getDeclaredField("sCache");
            sCacheField.setAccessible(true);
            Object cacheObj = sCacheField.get(null);
            if (cacheObj instanceof Map) {
                Map<?, ?> cache = (Map<?, ?>) cacheObj;
                synchronized (cache) {
                    Iterator<?> it = cache.keySet().iterator();
                    while (it.hasNext()) {
                        Object key = it.next();
                        if (key instanceof String && shouldHide((String) key)) {
                            it.remove();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }
}
