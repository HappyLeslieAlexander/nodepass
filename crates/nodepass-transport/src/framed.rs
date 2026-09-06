use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Writes a length-prefixed UDP datagram with a 2-byte big-endian header.
pub async fn write_udp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> io::Result<()> {
    if data.len() > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("datagram too large: {}", data.len()),
        ));
    }
    let header = (data.len() as u16).to_be_bytes();
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a length-prefixed UDP datagram with a 2-byte big-endian header into `buf`.
/// Applies optional `timeout`.
pub async fn read_udp_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    timeout: Duration,
) -> io::Result<usize> {
    if timeout > Duration::ZERO {
        match tokio::time::timeout(timeout, read_udp_frame_internal(reader, buf)).await {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "read UDP frame timed out",
            )),
        }
    } else {
        read_udp_frame_internal(reader, buf).await
    }
}

async fn read_udp_frame_internal<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    let length = u16::from_be_bytes(header) as usize;

    if length == 0 {
        return Ok(0);
    }

    if length > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("datagram too large: {} > buffer {}", length, buf.len()),
        ));
    }

    reader.read_exact(&mut buf[..length]).await?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_frame_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let data = b"Hello UDP World!";
        write_udp_frame(&mut client, data).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = read_udp_frame(&mut server, &mut buf, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(&buf[..n], data);
    }
}
