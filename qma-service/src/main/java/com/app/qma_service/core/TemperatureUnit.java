package com.app.qma_service.core;

import java.util.function.Function;

public enum TemperatureUnit implements Measurable {

	CELSIUS(false), FAHRENHEIT(true);

	private final boolean isFahrenheit;

	TemperatureUnit(boolean isFahrenheit) {
		this.isFahrenheit = isFahrenheit;
	}

	// Lambda conversions
	Function<Double, Double> FAHRENHEIT_TO_CELSIUS = f -> (f - 32) * 5 / 9;

	Function<Double, Double> CELSIUS_TO_CELSIUS = c -> c;

	@Override
	public String getUnitName() {
		return this.name();
	}

	@Override
	public double getConversionFactor() {
		return 1.0; // not used for temperature
	}

	@Override
	public double convertToBaseUnit(double value) {

		if (this == FAHRENHEIT)
			return FAHRENHEIT_TO_CELSIUS.apply(value);

		return CELSIUS_TO_CELSIUS.apply(value);
	}

	@Override
	public double convertFromBaseUnit(double baseValue) {

		if (this == FAHRENHEIT)
			return (baseValue * 9 / 5) + 32;

		return baseValue;
	}

	// temperature does NOT support arithmetic
	SupportsArithmetic supportsArithmetic = () -> false;

	@Override
	public boolean supportsArithmetic() {
		return supportsArithmetic.isSupported();
	}

	@Override
	public void validateOperationSupport(String operation) {

		if (!supportsArithmetic()) {
			throw new UnsupportedOperationException(this.name() + " does not support " + operation + " operation");
		}
	}
}
