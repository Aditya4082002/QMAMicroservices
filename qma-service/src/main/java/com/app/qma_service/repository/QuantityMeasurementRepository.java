package com.app.qma_service.repository;



import java.time.LocalDateTime;
import java.util.List;

import com.app.qma_service.model.QuantityMeasurementEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface QuantityMeasurementRepository
        extends JpaRepository<QuantityMeasurementEntity, Long> {

    //find by operation (ADD, SUBTRACT, etc.)
    List<QuantityMeasurementEntity> findByOperationAndUsername(String operation, String username);

    //get records after a certain time
    List<QuantityMeasurementEntity> findByCreatedAtAfter(LocalDateTime time);

    //count operations
    long countByOperation(String operation);
}
