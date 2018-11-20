import org.junit.Test;
import org.junit.After;

import vehicle.*;
import core.*;
public class CoreFirmwareTest {
    
   @Test
   public void testFirmwareValidation() {
      // Testing ECU firmware modification when firmware validation and programming mode authorization are enabled and firmware key is read. This allows complete network message injection.
      /*
         Ecu <---> Firmware
          |
          ---> Credentials(A)
      */
      // Entry point: Credentials.read and Ecu.access
      ECU ecu = new ECU("ECU", true, false, true); // Enabled programming mode authorization and message confliction protection.
      Firmware fw = new Firmware("Firmware", true); // Firmware validation is enabled.
      Credentials creds = new Credentials("Credentials");
      
      ecu.addFirmware(fw);
      ecu.addData(creds);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(creds.read);
      attacker.addAttackPoint(ecu.access);
      attacker.attack();
      
      ecu.passFirmwareValidation.assertCompromisedInstantaneously();
      ecu.uploadFirmware.assertCompromisedInstantaneously();
      ecu.maliciousFirmwareUpload.assertCompromisedWithEffort();
      fw.maliciousFirmwareModification.assertCompromisedInstantaneouslyFrom(ecu.changeOperationMode);
      //ecu.access.assertCompromisedInstantaneouslyFrom(ecu.maliciousFirmwareUpload);
    }
   
   @Test
   public void testFirmwareValidation2() {
      // Testing ECU firmware modification when firmware validation and programming mode authorization are enabled but firmware key is not present.
      /*
         Ecu(A) <---> Firmware
           |
           ---X No credentials are stored
      */
      // Entry point: Ecu.connect
      ECU ecu = new ECU("ECU", true, false, true); // Enabled programming mode authorization and message confliction protection.
      Firmware fw = new Firmware("Firmware", true); // Firmware validation is enabled.
      
      ecu.addFirmware(fw);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(ecu.connect);
      attacker.attack();

      ecu.attemptChangeOperationMode.assertCompromisedWithEffort();
      fw.maliciousFirmwareModification.assertCompromisedInstantaneouslyFrom(ecu.attemptChangeOperationMode);
      fw.bypassFirmwareValidation.assertUncompromised();
      //fw.bypassFirmwareValidation.assertUncompromisedFrom(ecu.connect);
      fw.crackFirmwareValidation.assertCompromisedWithEffort();
      ecu._maliciousProgrammingAccess.assertCompromisedInstantaneouslyFrom(fw.crackFirmwareValidation);
      ecu.bypassProgrammingModeAuthorization.assertUncompromised();
      ecu.crackProgrammingModeAuthorization.assertCompromisedWithEffort();
      ecu.maliciousFirmwareUpload.assertCompromisedWithEffort();
      ecu.access.assertCompromisedInstantaneouslyFrom(ecu.maliciousFirmwareUpload);
    }
   
   @Test
   public void testBypassFirmwareValidation() {
      // Testing ECU firmware modification when firmware validation and programming mode authorization are disabled. This means that anybody can upload a custom firmware.
      /*
         Ecu <---> Firmware
      */
      // Entry point: Ecu.connect
      ECU ecu = new ECU("ECU", false, false, true); // Enabled operation mode and message confliction protection.
      Firmware fw = new Firmware("Firmware", false); // Firmware validation is disabled.
      
      ecu.addFirmware(fw);

      Attacker attacker = new Attacker();
      attacker.addAttackPoint(ecu.connect);
      attacker.attack();
      
      fw.maliciousFirmwareModification.assertCompromisedInstantaneouslyFrom(ecu.attemptChangeOperationMode);
      fw.bypassFirmwareValidation.assertCompromisedInstantaneouslyFrom(fw.maliciousFirmwareModification);
      fw.crackFirmwareValidation.assertCompromisedWithEffort();
      ecu.bypassProgrammingModeAuthorization.assertCompromisedInstantaneouslyFrom(ecu._maliciousProgrammingAccess);
      ecu.crackProgrammingModeAuthorization.assertCompromisedWithEffort();
      ecu.access.assertCompromisedInstantaneouslyFrom(ecu.bypassProgrammingModeAuthorization);
    }
   
    @After
    public void deleteModel() {
            Asset.allAssets.clear();
            AttackStep.allAttackSteps.clear();
            Defense.allDefenses.clear();
    }
    
}
