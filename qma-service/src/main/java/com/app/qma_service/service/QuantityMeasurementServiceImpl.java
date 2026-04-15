package com.app.qma_service.service;

import java.util.List;
import java.util.stream.Collectors;

import com.app.qma_service.core.*;
import com.app.qma_service.dto.QuantityDTO;
import com.app.qma_service.dto.QuantityInputDTO;
import com.app.qma_service.dto.QuantityMeasurementDTO;
import com.app.qma_service.model.QuantityMeasurementEntity;
import com.app.qma_service.repository.QuantityMeasurementRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class QuantityMeasurementServiceImpl implements IQuantityMeasurementService {

	@Autowired
	private QuantityMeasurementRepository repository;

	// helper: convert DTO → Quantity
	private Quantity<?> toQuantity(QuantityDTO dto) {

		switch (dto.getMeasurementType()) {

			case "LENGTH":
				return new Quantity<>(dto.getValue(), LengthUnit.valueOf(dto.getUnit()));

			case "WEIGHT":
				return new Quantity<>(dto.getValue(), WeightUnit.valueOf(dto.getUnit()));

			case "VOLUME":
				return new Quantity<>(dto.getValue(), VolumeUnit.valueOf(dto.getUnit()));

			case "TEMPERATURE":
				return new Quantity<>(dto.getValue(), TemperatureUnit.valueOf(dto.getUnit()));

			default:
				throw new IllegalArgumentException("Invalid measurement type");
		}
	}

	// helper: save result
	private QuantityMeasurementDTO save(String operation, String op1, String op2, String result, String username) {

		QuantityMeasurementEntity entity = new QuantityMeasurementEntity(operation, op1, op2, result, username);

		entity = repository.save(entity);

		return QuantityMeasurementDTO.fromEntity(entity);
	}

	// COMPARE
	@Override
	public QuantityMeasurementDTO compare(QuantityInputDTO input, String username) {

		Quantity<?> q1 = toQuantity(input.getQuantity1());
		Quantity<?> q2 = toQuantity(input.getQuantity2());

		boolean res = q1.equals(q2);

		return save("COMPARE", q1.toString(), q2.toString(), String.valueOf(res), username);

	}

	// ADD
	@Override
	public QuantityMeasurementDTO add(QuantityInputDTO input, String username) {

		Quantity q1 = toQuantity(input.getQuantity1());
		Quantity q2 = toQuantity(input.getQuantity2());

		Quantity result = q1.add(q2);

		return save("ADD", q1.toString(), q2.toString(), result.toString(), username);

	}

	// SUBTRACT
	@Override
	public QuantityMeasurementDTO subtract(QuantityInputDTO input, String username) {

		Quantity q1 = toQuantity(input.getQuantity1());
		Quantity q2 = toQuantity(input.getQuantity2());

		Quantity result = q1.subtract(q2);

		return save("SUBTRACT", q1.toString(), q2.toString(), result.toString(), username);

	}

	// DIVIDE
	@Override
	public QuantityMeasurementDTO divide(QuantityInputDTO input, String username) {

		Quantity q1 = toQuantity(input.getQuantity1());
		Quantity q2 = toQuantity(input.getQuantity2());

		Quantity result = q1.divide(q2);

		return save("DIVIDE", q1.toString(), q2.toString(), result.toString(), username);

	}

	private Measurable getUnit(String type, String unitName) {

		switch (type.toUpperCase()) {

			case "LENGTH":
				return LengthUnit.valueOf(unitName);

			case "WEIGHT":
				return WeightUnit.valueOf(unitName);

			case "VOLUME":
				return VolumeUnit.valueOf(unitName);

			case "TEMPERATURE":
				return TemperatureUnit.valueOf(unitName);

			default:
				throw new IllegalArgumentException("Unsupported measurement type");
		}
	}

	// CONVERT
	@Override
	public QuantityMeasurementDTO convert(QuantityInputDTO input, String username) {

		QuantityDTO q1 = input.getQuantity1();

		Measurable source = getUnit(q1.getMeasurementType(),q1.getUnit());
		Measurable target = getUnit(q1.getMeasurementType(),input.getTargetUnit());

		Quantity<Measurable> quantity = new Quantity<>(q1.getValue(),source);
		Quantity<Measurable> result = quantity.convertTo(target);

		return save("CONVERT", q1.toString(), "-", result.toString(), username);

	}

	// HISTORY
	@Override
	public List<QuantityMeasurementDTO> getHistoryByOperation(String operation, String username) {

		return repository.findByOperationAndUsername(operation,username).stream().map(QuantityMeasurementDTO::fromEntity)
				.collect(Collectors.toList());
	}

	// COUNT
	@Override
	public long countByOperation(String operation) {
		return repository.countByOperation(operation);
	}
}
