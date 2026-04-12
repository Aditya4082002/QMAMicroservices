package com.app.qma_service.core;

public enum VolumeUnit implements Measurable{
	
	LITER(1.0),
	MILLILITER(0.001),
	GALLON(3.78541);
	
	private VolumeUnit(double conversionFactor) {
		this.conversionFactor = conversionFactor;
	}

	private final double conversionFactor;

	@Override
	public double getConversionFactor() {
		
		return conversionFactor;
	}

	@Override
	public double convertToBaseUnit(double value) {
		return value*conversionFactor;
	}

	@Override
	public double convertFromBaseUnit(double baseValue) {
		return baseValue/conversionFactor;
	}

	@Override
	public String getUnitName() {
		return this.name();
	}
	
}

