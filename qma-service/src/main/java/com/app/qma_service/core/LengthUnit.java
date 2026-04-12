package com.app.qma_service.core;

public enum LengthUnit implements Measurable {

	FEET(1.0), INCH(1.0 / 12.0), YARD(3.0), CENTIMETER(0.0328084167);

	private final double conversionFactor;

	LengthUnit(double conversionFactor) {
		this.conversionFactor = conversionFactor;
	}

	@Override
	public double getConversionFactor() {
		return conversionFactor;
	}

	@Override
	public double convertToBaseUnit(double value) {
		return value * conversionFactor;
	}

	@Override
	public double convertFromBaseUnit(double baseValue) {
		return baseValue / conversionFactor;
	}

	@Override
	public String getUnitName() {
		return this.name();
	}
}
