import React from 'react';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';
import Select from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import {getCryptoChoices, getCryptoParameterError} from './CryptoProviderChoices';
import {useCryptoProviders} from './CryptoProviderContext';

export function CryptoParameterSelect({name, display_name, description, choices, choices_display_names,
    trackedValue, default_value, supported_crypto_schemes, onChange, allowCustom = false, required, verifier_regex}){
    const discovery = useCryptoProviders();
    const value = trackedValue ?? default_value ?? "";
    const validate = candidate => getCryptoParameterError({value: candidate, required, verifier_regex}, supported_crypto_schemes, discovery);
    const error = validate(value);
    const options = getCryptoChoices(choices, choices_display_names, supported_crypto_schemes, discovery, value);
    const reported = React.useRef(null);
    React.useEffect(() => {
        const signature = JSON.stringify([name, value, Boolean(error)]);
        if(reported.current !== signature){
            reported.current = signature;
            onChange(name, value, Boolean(error));
        }
    }, [name, value, error, onChange]);
    const changeValue = event => onChange(name, event.target.value,
        Boolean(validate(event.target.value)));
    return (
        <div className="flex flex-column gap-3">
            <FormControl error={Boolean(error)} fullWidth>
                <Select native value={value} inputProps={{'aria-label': display_name || description || name}}
                    onChange={changeValue}>
                    {options.map(option => (
                        <option key={option.value} value={option.value} disabled={option.disabled}>{option.label}</option>
                    ))}
                </Select>
                {error && <FormHelperText role="alert">{error}</FormHelperText>}
            </FormControl>
            {allowCustom && <TextField value={value} label="Custom value" onChange={changeValue}
                required={required} error={Boolean(error)} multiline maxRows={5}
                inputProps={{'aria-label': 'Custom encryption value'}} />}
        </div>
    );
}
