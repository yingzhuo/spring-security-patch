/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.common;

import org.slf4j.Logger;

/**
 * @author 应卓
 * @since 1.1.3
 */
public final class Debugger {

    public static Debugger of(Logger logger, DebugMode debugMode) {
        return new Debugger(logger, debugMode);
    }

    private final Logger logger;
    private final DebugMode debugMode;

    private Debugger(Logger logger, DebugMode debugMode) {
        this.logger = logger;
        this.debugMode = debugMode;
    }

    public void debug(String format, Object... args) {
        if (debugMode == DebugMode.ENABLED && logger.isDebugEnabled()) {
            logger.debug(format, args);
        }
    }

}
