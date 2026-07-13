import { Global, Module } from '@nestjs/common';
import { KeystoreService } from './keystore.service';
import { RequestEncryptionService } from './request-encryption.service';

@Global()
@Module({
  providers: [KeystoreService, RequestEncryptionService],
  exports: [KeystoreService, RequestEncryptionService],
})
export class CryptoModule {}
