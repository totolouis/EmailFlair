import nodemailer from 'nodemailer';
import { IForwardOptions } from '../interfaces';

class ForwarderService {
  async forward(options: IForwardOptions): Promise<nodemailer.SentMessageInfo> {
    const { destinationHost, destinationPort = 25, from, to, rawMessage } = options;

    const transporter = nodemailer.createTransport({
      host: destinationHost,
      port: destinationPort,
      secure: false,
      tls: { rejectUnauthorized: false },
      connectionTimeout: 15000,
      greetingTimeout: 10000,
    });

    const info = await transporter.sendMail({
      envelope: { from, to },
      raw: rawMessage,
    });

    return info;
  }
}

const forwarderService = new ForwarderService();
export { forwarderService, ForwarderService };
export default forwarderService;
