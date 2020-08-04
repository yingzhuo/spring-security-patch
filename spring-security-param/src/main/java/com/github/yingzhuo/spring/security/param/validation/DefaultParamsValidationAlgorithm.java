/*                 _                                            _ _                           _       _
 *  ___ _ __  _ __(_)_ __   __ _       ___  ___  ___ _   _ _ __(_) |_ _   _       _ __   __ _| |_ ___| |__
 * / __| '_ \| '__| | '_ \ / _` |_____/ __|/ _ \/ __| | | | '__| | __| | | |_____| '_ \ / _` | __/ __| '_ \
 * \__ \ |_) | |  | | | | | (_| |_____\__ \  __/ (__| |_| | |  | | |_| |_| |_____| |_) | (_| | || (__| | | |
 * |___/ .__/|_|  |_|_| |_|\__, |     |___/\___|\___|\__,_|_|  |_|\__|\__, |     | .__/ \__,_|\__\___|_| |_|
 *     |_|                 |___/                                      |___/      |_|
 *
 *  https://github.com/yingzhuo/spring-security-patch
 */
package com.github.yingzhuo.spring.security.param.validation;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.TreeSet;

/**
 * @author 应卓
 * @since 1.1.3
 */
public class DefaultParamsValidationAlgorithm implements ParamsValidationAlgorithm {

    @Override
    public String merge(Map<String, String[]> params, String signParameterName) {
        final StringBuilder stringBuilder = new StringBuilder();

        for (String key : new TreeSet<>(params.keySet())) {

            if (signParameterName != null && signParameterName.equals(key)) {
                continue;
            }

            String[] values = params.get(key);
            String value = StringUtils.join(values, ',');
            stringBuilder.append(
                    String.format("%s=%s,", key, value)
            );
        }

        String string = stringBuilder.toString();
        if (string.endsWith(",")) {
            string = string.substring(0, string.length() - 1);
        }
        return string;
    }

    @Override
    public String encode(String mergedParams) {
        return DigestUtils.sha256Hex(DigestUtils.md5Hex(mergedParams));
    }

    @Override
    public boolean matches(String hashedParameters, String sign) {
        return StringUtils.equals(hashedParameters, sign);
    }

}
