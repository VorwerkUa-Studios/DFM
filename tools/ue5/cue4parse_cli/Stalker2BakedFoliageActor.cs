using CUE4Parse.UE4.Assets;
using CUE4Parse.UE4.Assets.Exports.Actor;
using CUE4Parse.UE4.Assets.Readers;
using Newtonsoft.Json;

public sealed class Stalker2BakedFoliageActor : AActor
{
    public long ArchiveStartOffset;
    public long ValidPosition;
    public long PositionAfterBaseDeserialize;
    public string? DeserializeError;

    public override void Deserialize(FAssetArchive archive, long validPosition)
    {
        ArchiveStartOffset = archive.Position;
        ValidPosition = validPosition;
        try
        {
            base.Deserialize(archive, validPosition);
        }
        catch (Exception error)
        {
            PositionAfterBaseDeserialize = archive.Position;
            DeserializeError = error.ToString();
            throw;
        }

        PositionAfterBaseDeserialize = archive.Position;
        archive.Position = validPosition;
    }

    protected override void WriteJson(JsonWriter writer, JsonSerializer serializer)
    {
        base.WriteJson(writer, serializer);
        writer.WritePropertyName(nameof(ArchiveStartOffset));
        writer.WriteValue(ArchiveStartOffset);
        writer.WritePropertyName(nameof(ValidPosition));
        writer.WriteValue(ValidPosition);
        writer.WritePropertyName(nameof(PositionAfterBaseDeserialize));
        writer.WriteValue(PositionAfterBaseDeserialize);
        if (DeserializeError is not null)
        {
            writer.WritePropertyName(nameof(DeserializeError));
            writer.WriteValue(DeserializeError);
        }
    }
}
