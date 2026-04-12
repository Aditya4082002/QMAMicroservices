package com.app.qma_service.service;

import com.app.qma_service.dto.QuantityInputDTO;
import com.app.qma_service.dto.QuantityMeasurementDTO;

import java.util.List;

public interface IQuantityMeasurementService {
   
    QuantityMeasurementDTO compare(QuantityInputDTO input,String username);

    QuantityMeasurementDTO add(QuantityInputDTO input,String username);

    QuantityMeasurementDTO subtract(QuantityInputDTO input,String username);

    QuantityMeasurementDTO divide(QuantityInputDTO input,String username);

    QuantityMeasurementDTO convert(QuantityInputDTO input,String username);

    List<QuantityMeasurementDTO> getHistoryByOperation(String operation,String username);

    long countByOperation(String operation);
}