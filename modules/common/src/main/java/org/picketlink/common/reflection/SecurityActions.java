/*
 *JBoss, Home of Professional Open Source
 *
 *Copyright 2016 Red Hat, Inc. and/or its affiliates.
 *
 *Licensed under the Apache License, Version 2.0 (the "License");
 *you may not use this file except in compliance with the License.
 *You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing, software
 *distributed under the License is distributed on an "AS IS" BASIS,
 *WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *See the License for the specific language governing permissions and
 *limitations under the License.
 */
package org.picketlink.common.reflection;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Privileged Blocks
 *
 * @author Ivo Studensky
 */
class SecurityActions {

    static ClassLoader getTCCL() {
        if (System.getSecurityManager() != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        } else {
            return Thread.currentThread().getContextClassLoader();
        }
    }

    static ClassLoader getClassLoader(final Class<?> clazz) {
        if (System.getSecurityManager() != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                @Override
                public ClassLoader run() {
                    return clazz.getClassLoader();
                }
            });
        } else {
            return clazz.getClassLoader();
        }
    }

    static <T> Constructor<T> getDeclaredConstructor(final Class<T> clazz) throws NoSuchMethodException {
        if (System.getSecurityManager() != null) {
            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction<Constructor<T>>() {
                    @Override
                    public Constructor<T> run() throws Exception {
                        return clazz.getDeclaredConstructor();
                    }
                });
            } catch (PrivilegedActionException pae) {
                throw (NoSuchMethodException) pae.getException();
            }
        }
        return clazz.getDeclaredConstructor();
    }

}