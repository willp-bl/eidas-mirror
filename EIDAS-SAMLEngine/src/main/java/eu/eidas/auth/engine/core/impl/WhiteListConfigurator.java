package eu.eidas.auth.engine.core.impl;

import java.util.Locale;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.collect.ImmutableSet;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

/**
 * WhiteListConfigurator
 *
 * @since 1.1
 */
public final class WhiteListConfigurator {

    private static final Pattern WHITE_LIST_SPLITTER = Pattern.compile("[;,]");

    @Nonnull
    public static ImmutableSet<String> getAllowedAlgorithms(@Nonnull ImmutableSet<String> defaultWhiteList,
                                                            @Nonnull ImmutableSet<String> allowedValues,
                                                            @Nullable String algorithmWhiteListValue) {
        if (StringUtils.isBlank(algorithmWhiteListValue)) {
            return defaultWhiteList;
        }
        ImmutableSet.Builder<String> allowed = ImmutableSet.builder();
        String[] wlAlgorithms = WHITE_LIST_SPLITTER.split(algorithmWhiteListValue);
        if (null != wlAlgorithms && wlAlgorithms.length > 0) {
            return getAllowedAlgorithms(defaultWhiteList, allowedValues, ImmutableSet.<String>copyOf(wlAlgorithms));
        }
        return defaultWhiteList;
    }

    @Nonnull
    public static ImmutableSet<String> getAllowedAlgorithms(@Nonnull ImmutableSet<String> defaultWhiteList,
                                                            @Nonnull ImmutableSet<String> allowedValues,
                                                            @Nullable ImmutableSet<String> candidateValues) {
        if (CollectionUtils.isEmpty(candidateValues)) {
            return defaultWhiteList;
        }
        ImmutableSet.Builder<String> allowed = ImmutableSet.builder();
        boolean modified = false;
        for (String candidateValue : candidateValues) {
            String candidateAlgorithm = StringUtils.trimToNull(candidateValue);
            if (StringUtils.isNotBlank(candidateAlgorithm)) {
                candidateAlgorithm = StringUtils.lowerCase(candidateAlgorithm, Locale.ENGLISH);
                if (allowedValues.contains(candidateAlgorithm)) {
                    allowed.add(candidateAlgorithm);
                    if (!modified && !candidateAlgorithm.equals(candidateValue)) {
                        modified = true;
                    }
                } else {
                    modified = true;
                }
            }
        }
        if (!modified) {
            return candidateValues;
        }
        ImmutableSet<String> set = allowed.build();
        if (set.isEmpty()) {
            return defaultWhiteList;
        }
        return set;
    }

    private WhiteListConfigurator() {
    }
}
