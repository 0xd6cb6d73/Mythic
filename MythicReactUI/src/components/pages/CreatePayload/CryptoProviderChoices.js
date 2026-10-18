import {GetGroupedParameters} from './BuildParameterUtils';

const identifier = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

export const isProviderSelection = (value) => typeof value === "string" && value.startsWith("provider:");

export const usesCryptoProviderSelector = (parameter) => Boolean(parameter.crypto_type &&
    ["String", "ChooseOne", "ChooseOneCustom"].includes(parameter.parameter_type) &&
    ((Array.isArray(parameter.supported_crypto_schemes) && parameter.supported_crypto_schemes.length > 0) ||
        isProviderSelection(parameter.trackedValue ?? parameter.default_value)));

export const parseProviderSelection = (value) => {
    if(!isProviderSelection(value)){
        return null;
    }
    const parts = value.split(":");
    return parts.length === 3 && identifier.test(parts[1]) && identifier.test(parts[2]) ?
        {name: parts[1], scheme: parts[2]} : null;
};

export const getCryptoSelectionError = (value, supportedSchemes, discovery) => {
    if(!isProviderSelection(value)){
        return "";
    }
    const selection = parseProviderSelection(value);
    if(!selection){
        return "Invalid cryptographic provider selection.";
    }
    if(!Array.isArray(supportedSchemes) || !supportedSchemes.includes(selection.scheme)){
        return "This payload type does not support the selected cryptographic scheme.";
    }
    if(discovery.loading){
        return "Loading cryptographic providers.";
    }
    if(discovery.error){
        return "Cryptographic provider discovery is unavailable.";
    }
    const provider = discovery.providers.find(candidate => candidate.name === selection.name && !candidate.deleted);
    if(!provider || !provider.container_running){
        return "The selected cryptographic provider is unavailable.";
    }
    if(!Array.isArray(provider.crypto_capabilities?.schemes) ||
        !provider.crypto_capabilities.schemes.includes(selection.scheme)){
        return "The selected cryptographic provider no longer supports this scheme.";
    }
    return "";
};

export const getCryptoChoices = (choices, displayNames, supportedSchemes, discovery, selectedValue) => {
    const builtinChoices = (Array.isArray(choices) ? choices : []).filter(choice => !isProviderSelection(choice));
    const options = builtinChoices.map(value => ({value, label: displayNames?.[value] || value, disabled: false}));
    const seen = new Set(builtinChoices);
    const allowed = new Set(Array.isArray(supportedSchemes) ? supportedSchemes : []);
    if(!discovery.loading && !discovery.error){
        for(const provider of discovery.providers){
            if(provider.deleted || !provider.container_running || typeof provider.name !== "string" || !identifier.test(provider.name) ||
                !Array.isArray(provider.crypto_capabilities?.schemes)){
                continue;
            }
            for(const scheme of provider.crypto_capabilities.schemes){
                const value = `provider:${provider.name}:${scheme}`;
                if(allowed.has(scheme) && identifier.test(scheme) && !seen.has(value)){
                    seen.add(value);
                    options.push({value, label: `${scheme} (${provider.name})`, disabled: false});
                }
            }
        }
    }
    if(isProviderSelection(selectedValue) && !seen.has(selectedValue)){
        const selection = parseProviderSelection(selectedValue);
        options.push({value: selectedValue, disabled: true,
            label: selection ? `${selection.scheme} (${selection.name}) — unavailable` : "Invalid provider selection"});
    }else if(typeof selectedValue === "string" && !seen.has(selectedValue)){
        options.push({value: selectedValue, label: displayNames?.[selectedValue] || selectedValue || "No selection", disabled: false});
    }
    return options;
};

export const getCryptoParameterError = (parameter, supportedSchemes, discovery) => {
    if(isProviderSelection(parameter.value)){
        return getCryptoSelectionError(parameter.value, supportedSchemes, discovery);
    }
    if(parameter.required && (parameter.value === "" || parameter.value === undefined || parameter.value === null)){
        return "A value is required.";
    }
    if(parameter.verifier_regex && parameter.value !== ""){
        try{
            if(!RegExp(parameter.verifier_regex).test(parameter.value)){
                return `Must match: ${parameter.verifier_regex}`;
            }
        }catch(error){
            return "Invalid parameter validation expression.";
        }
    }
    return "";
};

export const getCryptoParametersError = (parameters, supportedSchemes, discovery) => {
    for(const parameter of parameters || []){
        if(parameter.crypto_type){
            const error = getCryptoParameterError(parameter, supportedSchemes, discovery);
            if(error){
                return `${parameter.display_name || parameter.name}: ${error}`;
            }
        }
    }
    return "";
};

export const getBuildCryptoError = (buildOptions, discovery) => {
    const payload = buildOptions[1] || {};
    const supportedSchemes = payload.supported_crypto_schemes || [];
    const visible = (parameters, c2Name) => GetGroupedParameters({
        buildParameters: parameters || [], os: payload.os, c2_name: c2Name,
    }).flatMap(group => group.parameters);
    const parameters = [
        ...visible(payload.parameters),
        ...(buildOptions[3]?.c2 || []).flatMap(profile => visible(profile.c2profileparameters, profile.name)),
    ];
    return getCryptoParametersError(parameters, supportedSchemes, discovery);
};
