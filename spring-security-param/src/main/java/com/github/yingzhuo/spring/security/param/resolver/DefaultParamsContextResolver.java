/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.param.resolver;

import com.github.yingzhuo.spring.security.param.DefaultParamsContext;
import com.github.yingzhuo.spring.security.param.ParamsContext;
import org.springframework.web.context.request.NativeWebRequest;

/**
 * @author 应卓
 * @since 1.1.3
 */
public class DefaultParamsContextResolver implements ParamsContextResolver {

    private static final String NONCE_PARAM_NAME = "_nonce";
    private static final String TIMESTAMP_PARAM_NAME = "_timestamp";
    private static final String SIGN_PARAM_NAME = "_sign";

    @Override
    public String getSignParamName() {
        return SIGN_PARAM_NAME;
    }

    @Override
    public ParamsContext resolve(NativeWebRequest request) {
        String nonce = request.getParameter(NONCE_PARAM_NAME);
        String sign = request.getParameter(SIGN_PARAM_NAME);
        long timestamp;

        try {
            String timestampStr = request.getParameter(TIMESTAMP_PARAM_NAME);
            if (timestampStr == null) {
                timestamp = 0L;
            } else {
                timestamp = Long.parseLong(timestampStr);
            }
        } catch (NumberFormatException e) {
            timestamp = 0L;
        }

        return new DefaultParamsContext(nonce, timestamp, sign);
    }

}
